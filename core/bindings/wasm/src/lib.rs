//! WASM-facing API surface: a thin, byte-oriented facade over `crypto` for browser clients
//! (PLAN.md Phase 8). No cryptography is implemented here — `generate_identity`/`public_bytes`
//! mirror the same names and semantics as the UniFFI binding (`core/bindings/uniffi`), so the
//! documented core API surface is identical across native and WASM targets.
//!
//! ## Prekey bundles and session establishment
//!
//! `generate_prekey_bundle` serializes a receiver's PQXDH prekey bundle to a self-delimiting
//! byte vector (see `crypto::session::bundle_to_bytes`). `establish_session_from_bundle`
//! deserializes a peer's bundle bytes, verifies the signed-prekey signature against the bundle's
//! identity key, and runs PQXDH session establishment — returning an opaque `SessionHandle`.
//! `establish_with_malformed_prekey` mirrors desktop's `establish_with_malformed_prekey` contract:
//! it deliberately tampers a bundle and asserts the failure surfaces as a structured `WasmError`,
//! never a panic across the WASM boundary.
//!
//! ## Double Ratchet encrypt/decrypt
//!
//! `create_receiver_session` constructs a receiver (Bob) session from an identity — the
//! counterpart to `establish_session_from_bundle` (which constructs a sender/Alice session).
//! `encrypt_message` encrypts plaintext on an established sender session, returning the
//! self-describing wire envelope. `decrypt_message` decrypts an envelope on a receiver session,
//! returning the plaintext. All error paths — tampered ciphertext (AEAD MAC failure),
//! mismatched session, malformed/truncated envelope — surface as a structured `WasmError`,
//! never a panic across the WASM boundary.
//!
//! ## Sender Keys group encrypt/decrypt
//!
//! `group_create` / `group_add_member` / `group_remove_member` / `group_encrypt` /
//! `group_decrypt` expose the Sender Keys group crypto from `protocol::group`. A
//! `GroupHandle` wraps a `GroupSession`; membership is managed by public identity key
//! bytes; encrypt/decrypt delegate to the core implementation. All error paths —
//! non-member decrypt, removed-member post-rotation decrypt, malformed ciphertext —
//! surface as a structured `WasmError`, never a panic.

use wasm_bindgen::prelude::*;

use crypto::identity::{IdentityKeyPair, PublicIdentityKey};
use crypto::ratchet_session::{DoubleRatchetSession, SessionError};
use crypto::session;
use protocol::group::{GroupMember, GroupSession};

/// A structured, JS-visible error — the WASM analogue of desktop's `ShellError`. Every core
/// `Result::Err` that crosses the WASM boundary is mapped to this type so JS code can switch on
/// `kind` and display `message`, the same contract `clients/desktop-tauri` asserts for
/// `ShellError` serialization shape.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmError {
    kind: String,
    message: String,
}

#[wasm_bindgen]
impl WasmError {
    /// The error variant tag (e.g. `"MalformedBundle"`, `"Session"`). JS code switches on this.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// A human-readable detail string. JS code displays this to the user or logs it.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl WasmError {
    fn new(kind: &str, message: &str) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.to_string(),
        }
    }
}

impl From<SessionError> for WasmError {
    fn from(err: SessionError) -> Self {
        WasmError::new("Session", &err.to_string())
    }
}

impl From<std::io::Error> for WasmError {
    fn from(err: std::io::Error) -> Self {
        // Map PermissionDenied (non-member / removed-member) to a distinct kind so JS can
        // switch on it; everything else is a generic Group error.
        let kind = if err.kind() == std::io::ErrorKind::PermissionDenied {
            "NotMember"
        } else {
            "Group"
        };
        WasmError::new(kind, &err.to_string())
    }
}

/// An opaque handle to an established PQXDH session. Wraps the real Rust session state —
/// wasm-bindgen passes struct instances by value/reference directly, no serialization step.
#[wasm_bindgen]
pub struct SessionHandle {
    inner: DoubleRatchetSession,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle").finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl SessionHandle {
    // The session handle is opaque to JS — no getter methods are exposed. The handle exists
    // so session establishment returns a concrete typed value JS can hold and pass back, not a
    // raw JsValue. Encrypt/decrypt are free functions below that take &mut SessionHandle.
}

// ---------------------------------------------------------------------------
// Receiver session creation
// ---------------------------------------------------------------------------

/// Construct a receiver (Bob) session from an identity keypair. The receiver publishes a
/// prekey bundle (via [`publish_bundle_bytes`]) and then accepts inbound messages via
/// [`decrypt_message`]. This is the counterpart to [`establish_session_from_bundle`], which
/// constructs a sender (Alice) session.
///
/// # Errors
///
/// Returns `WasmError` if prekey generation or store initialization fails. In practice this
/// never happens with a freshly generated identity, but the error path is wired so a failure
/// surfaces as a structured error, never a panic.
#[wasm_bindgen]
pub fn create_receiver_session(
    identity_handle: &IdentityHandle,
) -> Result<SessionHandle, WasmError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| WasmError::new("Runtime", &e.to_string()))?;

    let session = runtime.block_on(async {
        DoubleRatchetSession::new_bob(identity_handle.inner.as_libsignal())
            .await
            .map_err(WasmError::from)
    })?;

    Ok(SessionHandle { inner: session })
}

/// Serialize the prekey bundle from an established receiver (Bob) session to a self-delimiting
/// byte vector. The bundle is generated from the *same* session state that will later decrypt
/// messages — so a sender who establishes from these bytes and encrypts will produce envelopes
/// this session can decrypt. Use [`generate_prekey_bundle`] when you only need the bundle bytes
/// (the receiver session is not retained); use this when you need both the bundle and the
/// session handle for a full encrypt/decrypt round-trip.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the session is not a publisher (i.e. it was
/// constructed as a sender via [`establish_session_from_bundle`]) or if serialization fails.
/// Never panics.
#[wasm_bindgen]
pub fn publish_bundle_bytes(session: &SessionHandle) -> Result<Vec<u8>, WasmError> {
    let bundle = session.inner.publish_bundle().map_err(WasmError::from)?;
    session::bundle_to_bytes(&bundle).map_err(|e| WasmError::new("PreKey", &e.to_string()))
}

// ---------------------------------------------------------------------------
// Double Ratchet encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` on an established sender (Alice) session, returning the self-describing
/// wire envelope (sender hash + type tag + raw ciphertext). The session state is advanced
/// (ratcheted) as part of encryption.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the session is receiver-only (no remote
/// address to encrypt to) or if the Double Ratchet encryption fails. Never panics.
#[wasm_bindgen]
pub fn encrypt_message(
    session: &mut SessionHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| WasmError::new("Runtime", &e.to_string()))?;

    runtime.block_on(async {
        session
            .inner
            .encrypt(plaintext)
            .await
            .map_err(WasmError::from)
    })
}

/// Decrypt a self-describing wire envelope on a receiver (Bob) session, returning the plaintext.
/// Fails closed on any malformed envelope, identity-hash mismatch, missing session, untrusted
/// identity, or MAC/AEAD authentication failure — no plaintext is produced on error.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the envelope is malformed/truncated, the
/// sender hash does not match the bound identity, no session exists for the sender, or AEAD
/// authentication fails (tampered ciphertext). Never panics.
#[wasm_bindgen]
pub fn decrypt_message(session: &mut SessionHandle, envelope: &[u8]) -> Result<Vec<u8>, WasmError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| WasmError::new("Runtime", &e.to_string()))?;

    runtime.block_on(async {
        session
            .inner
            .decrypt(envelope)
            .await
            .map_err(WasmError::from)
    })
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// An opaque handle to a Curve25519 identity keypair, exactly like the existing pattern.
/// Private fields are not visible to JS; only the `#[wasm_bindgen]` methods are.
#[wasm_bindgen]
pub struct IdentityHandle {
    inner: IdentityKeyPair,
}

#[wasm_bindgen]
impl IdentityHandle {
    /// Return the public identity key bytes (33-byte compressed Curve25519 key).
    pub fn public_bytes(&self) -> Vec<u8> {
        self.inner.public().to_bytes()
    }
}

/// Generate a fresh identity keypair from the OS CSPRNG.
#[wasm_bindgen]
pub fn generate_identity() -> IdentityHandle {
    IdentityHandle {
        inner: IdentityKeyPair::generate(),
    }
}

// ---------------------------------------------------------------------------
// Prekey bundle generation
// ---------------------------------------------------------------------------

/// Generate a PQXDH prekey bundle for the identity behind `identity_handle` and serialize it
/// to a self-delimiting byte vector (see `crypto::session::bundle_to_bytes`).
///
/// The bundle includes the identity key, a signed prekey, a Kyber KEM prekey, and a one-time
/// prekey. The byte format is an internal length-prefixed concatenation — it does NOT match
/// the `/spec` protobuf wire format (which carries transport-layer fields this struct excludes).
///
/// # Errors
///
/// Returns `WasmError` if prekey generation or serialization fails. In practice this never
/// happens with a freshly generated identity, but the error path is wired so a failure
/// surfaces as a structured error, never a panic.
#[wasm_bindgen]
pub fn generate_prekey_bundle(identity_handle: &IdentityHandle) -> Result<Vec<u8>, WasmError> {
    // Build a receiver (Bob) session — this generates signed/Kyber/one-time prekeys and
    // publishes a bundle. We then serialize that bundle to bytes.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| WasmError::new("Runtime", &e.to_string()))?;

    let bundle_bytes = runtime.block_on(async {
        let bob = DoubleRatchetSession::new_bob(identity_handle.inner.as_libsignal())
            .await
            .map_err(WasmError::from)?;
        let bundle = bob.publish_bundle().map_err(WasmError::from)?;
        session::bundle_to_bytes(&bundle).map_err(|e| WasmError::new("PreKey", &e.to_string()))
    })?;

    Ok(bundle_bytes)
}

// ---------------------------------------------------------------------------
// Session establishment from a peer's bundle bytes
// ---------------------------------------------------------------------------

/// Deserialize a peer's prekey bundle from `bundle_bytes`, verify the signed-prekey signature
/// against the bundle's identity key, and establish a PQXDH session — returning an opaque
/// `SessionHandle`.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "MalformedBundle"` if the bytes are truncated, mis-length-
/// prefixed, or structurally invalid. Returns `WasmError` with `kind = "PreKey"` if the
/// signed-prekey signature does not verify (tampered or unsigned bundle). Returns
/// `WasmError` with `kind = "Session"` if PQXDH session establishment fails. Never panics.
#[wasm_bindgen]
pub fn establish_session_from_bundle(
    identity_handle: &IdentityHandle,
    bundle_bytes: &[u8],
) -> Result<SessionHandle, WasmError> {
    // 1. Deserialize the bundle bytes — fail closed on any structural issue.
    let bundle = session::bundle_from_bytes(bundle_bytes).map_err(|_| {
        WasmError::new(
            "MalformedBundle",
            "malformed or truncated prekey bundle bytes",
        )
    })?;

    // 2. Establish the PQXDH session. `process_prekey_bundle` (called inside `new_alice`)
    //    verifies the signed-prekey and Kyber-prekey signatures against the bundle's identity
    //    key — a tampered or unsigned bundle fails closed here before any session state is
    //    written.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| WasmError::new("Runtime", &e.to_string()))?;

    let session = runtime.block_on(async {
        DoubleRatchetSession::new_alice(identity_handle.inner.as_libsignal(), &bundle)
            .await
            .map_err(WasmError::from)
    })?;

    Ok(SessionHandle { inner: session })
}

// ---------------------------------------------------------------------------
// Malformed-prekey contract test (mirrors desktop's establish_with_malformed_prekey)
// ---------------------------------------------------------------------------

/// Deliberately attempt PQXDH session establishment against a bundle with a tampered
/// signed-prekey signature, and return the resulting `Err` rather than panicking.
///
/// Mirrors `core_crypto::session::establish_with_malformed_prekey` and desktop's
/// `establish_malformed_session` command — the "a malformed core input surfaces as a defined
/// error state, not a crash" contract, exercised from the WASM boundary.
#[wasm_bindgen]
pub fn establish_with_malformed_prekey() -> Result<(), WasmError> {
    crypto::session::establish_with_malformed_prekey().map_err(WasmError::from)
}

// ---------------------------------------------------------------------------
// Browser threat model (unchanged from the original API)
// ---------------------------------------------------------------------------

/// The browser's key-storage security model, as distinct from a native client's.
///
/// A native client (desktop/iOS/Android) can rely on OS-level secure storage (Keychain,
/// Keystore, or at minimum a file the OS sandboxes per-app). A browser has no equivalent: an
/// identity private key generated in WASM either lives in JS-heap memory for the tab's
/// lifetime, or is persisted via IndexedDB/WebCrypto's non-extractable-key storage — neither
/// of which is backed by a secure enclave, and both are reachable by any other code that
/// achieves script execution in the same origin (e.g. a supply-chain-compromised dependency,
/// or an XSS if the app has that class of bug). This is a real, documented reduction in the
/// threat model relative to native clients, not a WASM implementation detail to paper over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserThreatModel {
    ReducedKeyStorage,
}

impl BrowserThreatModel {
    pub fn docs(&self) -> &'static str {
        match self {
            BrowserThreatModel::ReducedKeyStorage => {
                "Browser clients have no secure enclave. Identity and session key material \
                 is stored via IndexedDB / WebCrypto non-extractable keys, which protects \
                 against casual extraction but not against a same-origin script-execution \
                 compromise (e.g. a malicious dependency or XSS). This is a reduced \
                 key-storage security model compared to native clients, which can rely on \
                 OS-level secure storage (Keychain/Keystore). Users on browser clients should \
                 be informed of this reduced guarantee, particularly for long-lived identity \
                 keys."
            }
        }
    }
}

pub fn document_browser_threat_model() -> BrowserThreatModel {
    BrowserThreatModel::ReducedKeyStorage
}

// ---------------------------------------------------------------------------
// Sender Keys group encrypt/decrypt (PLAN.md Phase 8 — follow-on story)
//
// Thin WASM facade over `protocol::group::GroupSession`. No cryptography is
// implemented here — every function delegates to the core implementation. All
// error paths surface as a structured `WasmError` (kind + message), never a
// panic across the WASM boundary.
// ---------------------------------------------------------------------------

/// An opaque handle to a Sender Keys group session. Wraps the real Rust
/// `GroupSession` state — wasm-bindgen passes struct instances by reference,
/// no serialization step. JS code creates one via [`group_create`], mutates
/// membership via [`group_add_member`]/[`group_remove_member`], and
/// encrypts/decrypts via [`group_encrypt`]/[`group_decrypt`].
#[wasm_bindgen]
pub struct GroupHandle {
    inner: GroupSession,
}

impl std::fmt::Debug for GroupHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupHandle").finish_non_exhaustive()
    }
}

/// Create a new Sender Keys group session with the given sender identity. The
/// sender's public key seeds the initial chain key (see `GroupSession::new`).
///
/// The returned `GroupHandle` has no members yet — call [`group_add_member`]
/// before [`group_encrypt`] so the ciphertext carries per-member sealed
/// wrappers that members can open.
#[wasm_bindgen]
pub fn group_create(sender: &IdentityHandle) -> GroupHandle {
    GroupHandle {
        inner: GroupSession::new(sender.inner.public()),
    }
}

/// Add a member to the group by their public identity key bytes (33-byte
/// compressed Curve25519 key, as returned by `IdentityHandle::public_bytes`).
///
/// Returns a new `GroupHandle` — `GroupSession::add_member` consumes `self`
/// and returns a new session, so the caller must use the returned handle for
/// subsequent operations.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Group"` if the member key bytes are
/// malformed (the core `seal` call during encrypt will reject them). Never
/// panics.
#[wasm_bindgen]
pub fn group_add_member(group: &GroupHandle, member_pub_bytes: &[u8]) -> GroupHandle {
    // Clone the inner session and add the member. GroupSession::add_member
    // takes `self` by value, so we clone first (GroupSession derives Clone).
    let pubkey = PublicIdentityKey::from_bytes(member_pub_bytes);
    let new_session = group.inner.clone().add_member(GroupMember(pubkey));
    GroupHandle { inner: new_session }
}

/// Remove a member from the group and rotate the sender key in the same
/// operation — so the removal is forward-secure by default (the removed member
/// cannot decrypt any message sent afterward, even with the old chain key).
///
/// Returns a new `GroupHandle` with the member removed and the chain key
/// rotated to a fresh CSPRNG value.
///
/// # Errors
///
/// Never returns `Err` — removal of a non-existent member is a no-op (the
/// core `retain` simply doesn't match). The function signature returns
/// `GroupHandle` directly (not `Result`) to match the core API's infallible
/// `remove_member`.
#[wasm_bindgen]
pub fn group_remove_member(group: &GroupHandle, member_pub_bytes: &[u8]) -> GroupHandle {
    let pubkey = PublicIdentityKey::from_bytes(member_pub_bytes);
    // remove_member internally rotates the sender key — see GroupSession::remove_member.
    let new_session = group.inner.clone().remove_member(GroupMember(pubkey));
    GroupHandle { inner: new_session }
}

/// Encrypt `plaintext` as the sender, returning the self-describing wire
/// ciphertext (nonce | payload_len | AES-GCM payload | wrapper_count |
/// per-member sealed wrappers). The session's chain key is ratcheted forward
/// on every call, so no two messages reuse the same (key, nonce) pair.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Group"` if the group exceeds the
/// 255-member wire-format limit, or if sealing the per-message key to a
/// member fails (malformed member key). Never panics.
#[wasm_bindgen]
pub fn group_encrypt(
    group: &GroupHandle,
    sender: &IdentityHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    group
        .inner
        .encrypt_as(&sender.inner, plaintext)
        .map_err(WasmError::from)
}

/// Decrypt `ciphertext` as the given member identity. Finds the wrapper
/// addressed to the member, unseals it with the member's private identity key
/// to recover the per-message key, then decrypts the AES-GCM payload.
///
/// Fails closed on any malformed ciphertext, missing wrapper (non-member),
/// or AEAD authentication failure — no plaintext is produced on error.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "NotMember"` if the caller is not a group
/// member (no wrapper addressed to them, or they hold no private key to open
/// it). Returns `WasmError` with `kind = "Group"` if the ciphertext is
/// malformed/truncated or AEAD authentication fails (tampered ciphertext).
/// Never panics.
#[wasm_bindgen]
pub fn group_decrypt(
    group: &GroupHandle,
    member: &IdentityHandle,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    group
        .inner
        .decrypt_as(&member.inner, ciphertext)
        .map_err(WasmError::from)
}
