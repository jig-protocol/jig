use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt, channel::mpsc};
use serde_json::{Value, json};

use super::protocol::{RpcError, RpcRequest, RpcResponse};
use super::state::SharedState;

/// Handle a WebSocket connection
pub async fn ws_handler(stream: WebSocket, state: SharedState) {
    let (mut sender, mut receiver) = stream.split();
    let (tx, mut rx) = mpsc::unbounded();

    // Forward messages from channel to socket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.next().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Receive loop
    while let Some(Ok(Message::Text(text))) = receiver.next().await {
        if let Ok(req) = serde_json::from_str::<RpcRequest>(&text) {
            let resp = handle_request(req, &state, tx.clone()).await;
            let _ = tx.unbounded_send(Message::Text(serde_json::to_string(&resp).unwrap()));
        }
    }

    send_task.abort();
}

async fn handle_request(
    req: RpcRequest,
    state: &SharedState,
    tx: mpsc::UnboundedSender<Message>,
) -> RpcResponse {
    match req.method.as_str() {
        "auth.anonymous" => RpcResponse {
            id: req.id,
            result: Some(json!({ "token": "anon" })),
            error: None,
        },
        "subscribe.channel" => {
            if let Some(channel) = get_param_str(&req.params, "channel") {
                state.subscribe(channel.to_string(), tx);
                RpcResponse {
                    id: req.id,
                    result: Some(json!({ "subscription_id": channel })),
                    error: None,
                }
            } else {
                RpcResponse {
                    id: req.id,
                    result: None,
                    error: Some(RpcError::method_not_found()),
                }
            }
        }
        "message.send" => {
            let channel = get_param_str(&req.params, "channel").unwrap_or("");
            let content = get_param_str(&req.params, "content").unwrap_or("");
            state
                .broadcast(channel, Message::Text(content.to_string()))
                .await;
            RpcResponse {
                id: req.id,
                result: Some(json!({ "status": "ok" })),
                error: None,
            }
        }
        _ => RpcResponse {
            id: req.id,
            result: None,
            error: Some(RpcError::method_not_found()),
        },
    }
}

fn get_param_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key)?.as_str()
}
