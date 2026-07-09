// TypeScript stub for the wasm-pack output (core/bindings/wasm/pkg).
// Mirrors the real WASM API surface used by the web client so that tests
// can run without a full wasm-pack build.  The stub honours the same
// "returns a new handle / no in-place mutation" contract as the real
// Rust bindings (core/bindings/wasm/src/lib.rs).

export class IdentityHandle {
    publicBytes: Uint8Array;
    constructor(publicBytes: Uint8Array) { this.publicBytes = publicBytes; }
    public_bytes(): Uint8Array { return this.publicBytes; }
}

export class GroupHandle {
    members: Uint8Array[];
    constructor(members: Uint8Array[]) { this.members = members || []; }
}

const arrayEquals = (a: Uint8Array, b: Uint8Array): boolean =>
    a.length === b.length && a.every((v, i) => v === b[i]);

export function generate_identity(): IdentityHandle {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return new IdentityHandle(bytes);
}

export function group_create(selfIdentity: IdentityHandle): GroupHandle {
    return new GroupHandle([selfIdentity.public_bytes()]);
}

export function group_add_member(group: GroupHandle, publicBytes: Uint8Array): GroupHandle {
    if (group.members.some(b => arrayEquals(b, publicBytes))) return group;
    // Return a NEW GroupHandle with a new members array — do NOT mutate the
    // input.  This matches the real WASM API which consumes self and produces
    // a fresh handle, and avoids aliasing bugs in React state where the same
    // object reference would be mutated (breaking memoization/equality checks).
    return new GroupHandle([...group.members, publicBytes]);
}

export function group_remove_member(group: GroupHandle, publicBytes: Uint8Array): GroupHandle {
    // Return a NEW GroupHandle with a new members array — do NOT mutate the
    // input (see group_add_member rationale).
    return new GroupHandle(group.members.filter(b => !arrayEquals(b, publicBytes)));
}

export function group_encrypt(group: GroupHandle, senderIdentity: IdentityHandle, plaintextBytes: Uint8Array): Uint8Array {
    const encoded = btoa(String.fromCharCode(...plaintextBytes));
    return Uint8Array.from(atob(encoded).split('').map(c => c.charCodeAt(0)));
}

export function group_decrypt(group: GroupHandle, memberIdentity: IdentityHandle, ciphertext: Uint8Array): Uint8Array {
    const publicKey = memberIdentity.public_bytes();
    if (!group.members.some(b => arrayEquals(b, publicKey))) throw new Error('decryption failed');
    const decoded = atob(String.fromCharCode(...ciphertext));
    return Uint8Array.from(decoded.split('').map(c => c.charCodeAt(0)));
}

export function derive_safety_number(localIdentityKey: Uint8Array, remoteIdentityKey: Uint8Array): string {
    const concat = new Uint8Array([...localIdentityKey, ...remoteIdentityKey]);
    return btoa(String.fromCharCode(...concat));
}
