use std::sync::Arc;

use axum::extract::ws::Message;
use dashmap::DashMap;
use futures::channel::mpsc::UnboundedSender;

/// Shared connection state
#[derive(Default)]
pub struct State {
    channels: DashMap<String, Vec<UnboundedSender<Message>>>,
}

pub type SharedState = Arc<State>;

impl State {
    /// Subscribe a sender to a channel
    pub fn subscribe(&self, channel: String, tx: UnboundedSender<Message>) {
        self.channels.entry(channel).or_default().push(tx);
    }

    /// Broadcast a message to all subscribers of a channel
    pub async fn broadcast(&self, channel: &str, msg: Message) {
        if let Some(mut senders) = self.channels.get_mut(channel) {
            senders.retain(|tx| tx.unbounded_send(msg.clone()).is_ok());
        }
    }
}
