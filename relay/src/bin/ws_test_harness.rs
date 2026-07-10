//! Test-only binary: start the relay WebSocket listener on a random localhost
//! port, print the bound address to stdout (first line, e.g. `ws://127.0.0.1:39124`),
//! and run until the process is killed.
//!
//! Used by the web client's cross-language integration test
//! (`clients/web/tests/relay_integration.test.ts`) which spawns this binary,
//! reads the address, and connects via the TypeScript `RelayTransport` to
//! verify a `send_envelope` → `pickup_envelope` round-trip against the *real*
//! relay — closing the contract gap between the Rust relay and the TS client.
//!
//! This binary is not shipped in production builds; it exists solely to give
//! the JS test runner a real relay endpoint to talk to.

use relay::ws;
use std::io::Write;

#[tokio::main]
async fn main() {
    // High rate limit so the integration test is never throttled.
    let handle = ws::start_ws_listener_for_test(10_000).await;
    let addr = handle.addr;

    // Print the WebSocket URL on the first line of stdout. The test harness
    // reads this line to discover the dynamically-bound port.
    let url = format!("ws://{addr}\n");
    {
        let mut stdout = std::io::stdout();
        stdout.write_all(url.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }

    // Run until the process is killed (the test harness sends SIGTERM / closes
    // stdin). We just sleep indefinitely — the test is responsible for tearing
    // the process down.
    //
    // We keep the handle alive so the listener task is not aborted.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}