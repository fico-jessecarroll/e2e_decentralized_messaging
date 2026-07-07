//! WASM-facing API surface: a thin, byte-oriented facade over `crypto` for browser clients
//! (PLAN.md Phase 8). No cryptography is implemented here — `generate_identity`/`public_bytes`
//! mirror the same names and semantics as the UniFFI binding (`core/bindings/uniffi`), so the
//! documented core API surface is identical across native and WASM targets.

pub mod api {
    use crypto::identity::IdentityKeyPair;

    pub struct IdentityHandle {
        inner: IdentityKeyPair,
    }

    impl IdentityHandle {
        pub fn public_bytes(&self) -> Vec<u8> {
            self.inner.public().to_bytes()
        }
    }

    pub fn generate_identity() -> IdentityHandle {
        IdentityHandle { inner: IdentityKeyPair::generate() }
    }

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
}
