// Thin UI wiring: every button calls a Tauri command that delegates straight into
// `core_crypto` (src-tauri/src/commands.rs). No crypto or session logic lives here — this file
// only renders the command's success value or its typed error state
// (src-tauri/src/error.rs::ShellError), never a raw exception/panic message.
const { invoke } = window.__TAURI__.core;

const output = document.getElementById("output");

function renderError(err) {
  output.textContent = `error: ${err.kind}: ${err.message}`;
}

function renderSuccess(value) {
  output.textContent = `ok: ${JSON.stringify(value)}`;
}

document.getElementById("generate").addEventListener("click", async () => {
  try {
    const publicKeyBytes = await invoke("generate_identity");
    renderSuccess(publicKeyBytes);
  } catch (err) {
    renderError(err);
  }
});

document.getElementById("malformed").addEventListener("click", async () => {
  try {
    await invoke("establish_malformed_session");
    renderSuccess("unexpected success");
  } catch (err) {
    renderError(err);
  }
});
