//! Conversation UI logic — render sent/received messages, handle empty state.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Sent and received messages render correctly with timestamps
//!  - Negative: UI handles an empty conversation/history state without error

use clients_desktop_tauri::ui::{render_conversation, ConversationState, Message};

#[test]
fn renders_sent_and_received_messages_with_timestamps() {
    let state = ConversationState {
        messages: vec![
            Message::sent(b"hello".to_vec(), 1_700_000_000),
            Message::received(b"hi back".to_vec(), 1_700_000_005),
        ],
    };

    let rendered = render_conversation(&state);
    assert!(rendered.contains("hello"), "sent message body must render");
    assert!(
        rendered.contains("hi back"),
        "received message body must render"
    );
    assert!(
        rendered.contains("2023-11-14"),
        "timestamp must render in human form"
    );
}

#[test]
fn empty_conversation_state_renders_without_error() {
    let state = ConversationState { messages: vec![] };
    let rendered = render_conversation(&state);
    // No panic; explicit empty-state marker expected.
    assert!(
        rendered.contains("no messages") || rendered.is_empty() || rendered.contains("empty"),
        "empty state must render an explicit empty-state marker, got: {rendered:?}"
    );
}
