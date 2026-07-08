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

use wasm_bindgen::prelude::*;

use crypto::identity::IdentityKeyPair;
use crypto::ratchet_session::{DoubleRatchetSession, SessionError};
use crypto::session;

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

/// An opaque handle to an established PQXDH session. Wraps the real Rust session state —
/// wasm-bindgen passes struct instances by value/reference directly, no serialization step.
#[wasm_bindgen]
#[allow(dead_code)] // encrypt/decrypt is a separate follow-on story
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
    // The session handle is opaque to JS — no methods are exposed here yet. Double Ratchet
    // encrypt/decrypt is a separate follow-on story. The handle exists so session establishment
    // returns a concrete typed value JS can hold and pass back, not a raw JsValue.
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
