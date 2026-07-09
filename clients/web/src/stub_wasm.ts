export class IdentityHandle {
    constructor(publicBytes) { this.publicBytes = publicBytes; }
    public_bytes() { return this.publicBytes; }
}
export class GroupHandle {
    constructor(members) { this.members = members || []; }
}
const arrayEquals = (a, b) => a.length === b.length && a.every((v,i)=>v===b[i]);
export function generate_identity() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return new IdentityHandle(bytes);
}
export function group_create(selfIdentity) { return new GroupHandle([selfIdentity.public_bytes()]); }
export function group_add_member(group, publicBytes) {
    if (!group.members.some(b=>arrayEquals(b,publicBytes))) group.members.push(publicBytes);
    return group;
}
export function group_remove_member(group, publicBytes){
    group.members = group.members.filter(b=>!arrayEquals(b,publicBytes));
    return group;
}
export function group_encrypt(group,senderIdentity,plaintextBytes){
    const encoded=btoa(String.fromCharCode(...plaintextBytes));
    return Uint8Array.from(atob(encoded).split('').map(c=>c.charCodeAt(0)));
}
export function group_decrypt(group,memberIdentity,ciphertext){
    const publicKey=memberIdentity.public_bytes();
    if (!group.members.some(b=>arrayEquals(b,publicKey))) throw new Error('decryption failed');
    const decoded=atob(String.fromCharCode(...ciphertext));
    return Uint8Array.from(decoded.split('').map(c=>c.charCodeAt(0)));
}
export function derive_safety_number(localIdentityKey,remoteIdentityKey){
    const concat=new Uint8Array([...localIdentityKey,...remoteIdentityKey]);
    return btoa(String.fromCharCode(...concat));
}
