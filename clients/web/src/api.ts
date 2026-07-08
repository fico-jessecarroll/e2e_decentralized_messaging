export function threatModelWarning(): string {
    return 'Reduced threat model: no secure enclave, browser key-storage';
}

export async function performSmokeFlow(plaintext: Uint8Array): Promise<Uint8Array> {
    // Derive a 256‑bit AES‑GCM key from the plaintext via SHA‑256
    const hash = await crypto.subtle.digest('SHA-256', plaintext.buffer as ArrayBuffer);
    const key = await crypto.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        key,
        plaintext.buffer as ArrayBuffer,
    );
    const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        key,
        cipher,
    );
    return new Uint8Array(dec);
}
