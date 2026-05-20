use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Request ID
    pub id: Option<Value>,
    /// Method name
    pub method: String,
    /// Parameters
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Request ID
    pub id: Option<Value>,
    /// Result payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
}

impl RpcError {
    /// Standard method not found error
    pub fn method_not_found() -> Self {
        Self {
            code: -32601,
            message: "Method not found".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_request() {
        let req = RpcRequest {
            id: Some(Value::from(1)),
            method: "test.method".into(),
            params: Value::Null,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("test.method"));
    }
}
