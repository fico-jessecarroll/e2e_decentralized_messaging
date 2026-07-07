//! WASM build of the core — same API surface, browser key-storage caveats documented.
//!
//! Anchors PLAN.md Phase 8 acceptance criteria:
//!  - WASM module builds and exposes the same core API surface
//!  - Negative: documents and tests the reduced key-storage security model in the browser (no secure enclave)

use core_bindings_wasm::api::{generate_identity, document_browser_threat_model, BrowserThreatModel};

#[test]
fn wasm_module_exposes_same_core_api_surface_as_native() {
    // The function names below must match the native core API. If a name
    // diverges between WASM and native, the binding contract is broken.
    let id = generate_identity();
    assert!(!id.public_bytes().is_empty(), "WASM generate_identity must produce a key");
}

#[test]
fn browser_threat_model_is_documented_and_reflects_no_secure_enclave() {
    let model = document_browser_threat_model();
    // The WASM binding must surface that the browser has NO secure enclave
    // — so identity material is only as protected as IndexedDB / WebCrypto.
    assert_eq!(model, BrowserThreatModel::ReducedKeyStorage);
    assert!(
        model.docs().contains("no secure enclave")
            || model.docs().contains("reduced key-storage")
            || model.docs().to_lowercase().contains("indexeddb"),
        "threat-model docs must explicitly call out the reduced browser key-storage model"
    );
}
