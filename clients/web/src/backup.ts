/**
 * Encrypted backup export/import — TypeScript port of core/storage/src/backup.rs.
 *
 * Wire format (identical to the Rust implementation):
 * ┌──────────┬─────┬────────┬────────┬────────┬────────────┐
 * │ Magic 4B │ Ver │ Salt16 │ Nonce12│ Tag16* │ Ciphertext │
 * │ "ECB1"   │ u8  │Argon2id│AES-GCM │ (in ct)│ record list│
 * └──────────┴─────┴────────┴────────┴────────┴────────────┘
 *
 * *AES-256-GCM via WebCrypto appends the 16-byte auth tag to the ciphertext,
 * matching the Rust aes-gcm crate's behaviour — so the tag is not a separate
 * field in the blob; it is the trailing 16 bytes of the ciphertext region.
 *
 * Inner plaintext (post-decryption):
 * ┌──────────────┬────────────────────┐
 * │ n_records u32│ record[0]          │ ...
 * │ big-endian   │ len u32 BE ‖ bytes │
 * └──────────────┴────────────────────┘
 *
 * The header (magic ‖ version ‖ salt ‖ nonce) is bound into the AEAD's
 * associated data via SHA-256, so flipping any header byte is detected.
 *
 * KDF: Argon2id (m=19 MiB, t=2, p=1, output=32 bytes) — same parameters as
 * the Rust implementation, via hash-wasm (WASM build of the reference
 * Argon2 C library). This ensures cross-platform format compatibility.
 *
 * Security properties (parity with core/storage/src/backup.rs):
 *  - Exported blob never contains plaintext record bytes.
 *  - Import is atomic: on any failure (tampered, wrong passphrase, malformed),
 *    zero records are returned and existing state is untouched.
 *  - Error variants are narrow and do not leak sensitive information.
 */

import { argon2id } from 'hash-wasm';

// ── Constants (must match core/storage/src/backup.rs) ──────────────────────

const MAGIC = new Uint8Array([0x45, 0x43, 0x42, 0x31]); // "ECB1"
const VERSION = 1;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16; // AES-256-GCM auth tag (embedded in ciphertext by WebCrypto)

// Argon2id parameters — OWASP "interactive" profile, matching the Rust impl.
const ARGON2_MEM_KIB = 19 * 1024; // 19 MiB
const ARGON2_TIME_COST = 2;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN = 32;

// Minimum blob size: magic(4) + version(1) + salt(16) + nonce(12) + tag(16) + at least 4 bytes inner
const MIN_BLOB_SIZE = MAGIC.length + 1 + SALT_LEN + NONCE_LEN + TAG_LEN + 4;

// ── Error types ────────────────────────────────────────────────────────────

/** Error kind — mirrors Rust's BackupError enum. */
export enum BackupErrorKind {
    /** Blob is structurally invalid, truncated, bad magic/version, or tampered. */
    Tampered = 'Tampered',
    /** Passphrase is wrong (AEAD authentication failed). */
    DecryptionFailed = 'DecryptionFailed',
    /** Internal misuse — e.g. zero records requested for export. */
    Empty = 'Empty',
}

export class BackupError extends Error {
    readonly kind: BackupErrorKind;

    constructor(kind: BackupErrorKind) {
        // Messages are deliberately non-leaky: no plaintext, ciphertext, or key terminology.
        const messages: Record<BackupErrorKind, string> = {
            [BackupErrorKind.Tampered]: 'backup file is corrupted or invalid',
            [BackupErrorKind.DecryptionFailed]: 'backup could not be opened — check your passphrase',
            [BackupErrorKind.Empty]: 'no records to export',
        };
        super(messages[kind]);
        this.name = 'BackupError';
        this.kind = kind;
    }
}

// ── Byte helpers ───────────────────────────────────────────────────────────

function writeU32BE(value: number): Uint8Array {
    const out = new Uint8Array(4);
    const view = new DataView(out.buffer);
    view.setUint32(0, value, false); // big-endian
    return out;
}

function readU32BE(buf: Uint8Array, offset: number): number {
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 4);
    return view.getUint32(0, false); // big-endian
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

// ── Record serialization (matches Rust serialize_records / deserialize_records) ──

function serializeRecords(records: Uint8Array[]): Uint8Array {
    const parts: Uint8Array[] = [writeU32BE(records.length)];
    for (const r of records) {
        parts.push(writeU32BE(r.length));
        parts.push(r);
    }
    return concatBytes(...parts);
}

function deserializeRecords(buf: Uint8Array): Uint8Array[] {
    if (buf.length < 4) {
        throw new BackupError(BackupErrorKind.Tampered);
    }
    const n = readU32BE(buf, 0);
    if (n === 0) {
        throw new BackupError(BackupErrorKind.Tampered);
    }

    let off = 4;
    const out: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
        if (off + 4 > buf.length) {
            throw new BackupError(BackupErrorKind.Tampered);
        }
        const len = readU32BE(buf, off);
        off += 4;
        if (off + len > buf.length) {
            throw new BackupError(BackupErrorKind.Tampered);
        }
        out.push(buf.slice(off, off + len));
        off += len;
    }
    // Reject trailing bytes — format is fully determined by n (parity with Rust).
    if (off !== buf.length) {
        throw new BackupError(BackupErrorKind.Tampered);
    }
    return out;
}

// ── AAD construction (matches Rust build_aad) ──────────────────────────────

async function buildAAD(salt: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
    const header = concatBytes(MAGIC, new Uint8Array([VERSION]), salt, nonce);
    const hashBuf = await crypto.subtle.digest('SHA-256', header.buffer as ArrayBuffer);
    return new Uint8Array(hashBuf);
}

// ── Key derivation (matches Rust derive_key — Argon2id) ────────────────────

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    return argon2id({
        password: encoder.encode(passphrase),
        salt,
        parallelism: ARGON2_PARALLELISM,
        iterations: ARGON2_TIME_COST,
        memorySize: ARGON2_MEM_KIB,
        hashLength: ARGON2_HASH_LEN,
        outputType: 'binary',
    });
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Encrypt `records` under `passphrase` and return a self-contained backup blob.
 *
 * The blob layout is documented at the module level. A fresh salt and nonce
 * are drawn from the CSPRNG for every call, so two exports of identical
 * records under the same passphrase produce different ciphertexts.
 *
 * @throws {BackupError} with kind `Empty` if records is empty.
 */
export async function exportBackup(
    passphrase: string,
    records: Uint8Array[],
): Promise<Uint8Array> {
    if (records.length === 0) {
        throw new BackupError(BackupErrorKind.Empty);
    }

    // 1. Fresh salt + nonce
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));

    // 2. Derive AEAD key
    const keyBytes = await deriveKey(passphrase, salt);

    // 3. Serialize records
    const plaintext = serializeRecords(records);

    // 4. Build AAD = SHA256(magic ‖ version ‖ salt ‖ nonce)
    const aad = await buildAAD(salt, nonce);

    // 5. Encrypt with AES-256-GCM
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBytes.buffer as ArrayBuffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt'],
    );
    const ciphertextBuf = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: nonce.buffer as ArrayBuffer,
            additionalData: aad.buffer as ArrayBuffer,
            tagLength: TAG_LEN * 8,
        },
        cryptoKey,
        plaintext.buffer as ArrayBuffer,
    );
    const ciphertextWithTag = new Uint8Array(ciphertextBuf);

    // 6. Assemble blob: magic ‖ version ‖ salt ‖ nonce ‖ ciphertext+tag
    return concatBytes(
        MAGIC,
        new Uint8Array([VERSION]),
        salt,
        nonce,
        ciphertextWithTag,
    );
}

/**
 * Decrypt `blob` under `passphrase` and return the original record list.
 *
 * All failure modes collapse to either `Tampered` (structural corruption) or
 * `DecryptionFailed` (wrong passphrase / AEAD auth failure). In no failure
 * case is any record returned — the import is atomic.
 *
 * @throws {BackupError} with kind `Tampered` or `DecryptionFailed`.
 */
export async function importBackup(
    passphrase: string,
    blob: Uint8Array,
): Promise<Uint8Array[]> {
    // Minimum size check
    if (blob.length < MIN_BLOB_SIZE) {
        throw new BackupError(BackupErrorKind.Tampered);
    }

    // Magic check
    for (let i = 0; i < MAGIC.length; i++) {
        if (blob[i] !== MAGIC[i]) {
            throw new BackupError(BackupErrorKind.Tampered);
        }
    }

    // Version check
    if (blob[MAGIC.length] !== VERSION) {
        throw new BackupError(BackupErrorKind.Tampered);
    }

    let off = MAGIC.length + 1;
    const salt = blob.slice(off, off + SALT_LEN);
    off += SALT_LEN;
    const nonce = blob.slice(off, off + NONCE_LEN);
    off += NONCE_LEN;
    const ciphertextWithTag = blob.slice(off);

    // Derive key and build AAD
    const aad = await buildAAD(salt, nonce);
    const keyBytes = await deriveKey(passphrase, salt);

    // Attempt decryption
    let plaintext: Uint8Array;
    try {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBytes.buffer as ArrayBuffer,
            { name: 'AES-GCM' },
            false,
            ['decrypt'],
        );
        const plainBuf = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce.buffer as ArrayBuffer,
                additionalData: aad.buffer as ArrayBuffer,
                tagLength: TAG_LEN * 8,
            },
            cryptoKey,
            ciphertextWithTag.buffer as ArrayBuffer,
        );
        plaintext = new Uint8Array(plainBuf);
    } catch {
        throw new BackupError(BackupErrorKind.DecryptionFailed);
    }

    // Deserialize records
    return deserializeRecords(plaintext);
}