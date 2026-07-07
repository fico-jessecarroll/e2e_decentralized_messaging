//! Conversation UI rendering — sent/received message history for the desktop shell.
//!
//! This is a thin presentation layer: it renders `ConversationState` (built from
//! locally decrypted message history) into a string the Tauri frontend displays.
//! No cryptography or storage logic lives here — that's owned by `core_crypto` /
//! `core_storage`.

use chrono::{DateTime, Utc};

/// Which side of the conversation a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

/// A single conversation message, already decrypted to plaintext bytes.
#[derive(Debug, Clone)]
pub struct Message {
    pub direction: Direction,
    pub body: Vec<u8>,
    pub unix_ts: i64,
}

impl Message {
    pub fn sent(body: Vec<u8>, unix_ts: i64) -> Self {
        Self {
            direction: Direction::Sent,
            body,
            unix_ts,
        }
    }

    pub fn received(body: Vec<u8>, unix_ts: i64) -> Self {
        Self {
            direction: Direction::Received,
            body,
            unix_ts,
        }
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn human_timestamp(&self) -> String {
        DateTime::<Utc>::from_timestamp(self.unix_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("invalid timestamp ({})", self.unix_ts))
    }
}

/// The full state of a conversation as displayed by the UI.
pub struct ConversationState {
    pub messages: Vec<Message>,
}

/// Render a conversation into the string the Tauri frontend displays.
///
/// Renders an explicit empty-state marker rather than an empty or panicking
/// output when there is no history yet.
pub fn render_conversation(state: &ConversationState) -> String {
    if state.messages.is_empty() {
        return "no messages yet".to_string();
    }

    state
        .messages
        .iter()
        .map(|message| {
            let sender = match message.direction {
                Direction::Sent => "You",
                Direction::Received => "Them",
            };
            format!(
                "[{}] {}: {}",
                message.human_timestamp(),
                sender,
                message.body_text()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
