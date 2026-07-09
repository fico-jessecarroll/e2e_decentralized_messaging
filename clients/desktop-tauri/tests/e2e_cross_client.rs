// Cross-client end-to-end smoke test: web and desktop clients exchange verified messages.
//
// This is a placeholder for the cross‑client integration test. The full
// implementation will launch a headless browser instance of the web client
// (via Playwright or a Node harness) and a desktop‑tauri process, then have
// them communicate through the relay stack.  Until that logic is added this
// test intentionally fails to signal that the feature is pending.

#[tokio::test]
async fn cross_client_smoke_test() {
    // TODO: implement cross-client messaging via WebSocket relay.
    panic!("cross‑client smoke test not yet implemented");
}
