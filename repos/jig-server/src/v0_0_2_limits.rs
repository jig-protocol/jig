//! `[limits]`: the most bytes this server reads in one HTTP request body or
//! one WebSocket message, from clients and from its federation peers.
//!
//! Each limit is explicit. Unset, it is
//! [`jig_core::bundle::MAX_ENVELOPE_BYTES`], the smallest that still carries
//! every block: a `MAX_BUNDLE_BYTES` bundle in base64 plus its envelope. A
//! smaller limit would turn valid blocks away, so boot refuses one.

use jig_config::v0_0_2_server::LimitsSection;
use jig_core::bundle::MAX_ENVELOPE_BYTES;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// `[limits]` with its defaults filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub request_body: usize,
    pub ws_message: usize,
    pub ws_frame: usize,
}

impl Limits {
    /// The limits `cfg` sets, defaults filled in. Not checked: boot runs
    /// [`Limits::validate`] first.
    pub fn resolve(cfg: &LimitsSection) -> Self {
        Self {
            request_body: cfg.max_request_body_bytes.unwrap_or(MAX_ENVELOPE_BYTES),
            ws_message: cfg.max_ws_message_bytes.unwrap_or(MAX_ENVELOPE_BYTES),
            ws_frame: cfg.max_ws_frame_bytes.unwrap_or(MAX_ENVELOPE_BYTES),
        }
    }

    /// Refuse limits that would turn valid blocks away, or a frame limit no
    /// message could reach.
    pub fn validate(cfg: &LimitsSection) -> Result<Self, String> {
        let limits = Self::resolve(cfg);
        for (key, value) in [
            ("max_request_body_bytes", limits.request_body),
            ("max_ws_message_bytes", limits.ws_message),
            ("max_ws_frame_bytes", limits.ws_frame),
        ] {
            if value < MAX_ENVELOPE_BYTES {
                return Err(format!(
                    "[limits] {key} = {value} is below {MAX_ENVELOPE_BYTES}, the size of the \
                     largest block submission (a {} byte bundle in base64, and its envelope): \
                     valid blocks would be refused. Leave it unset for that minimum.",
                    jig_core::bundle::MAX_BUNDLE_BYTES
                ));
            }
        }
        if limits.ws_frame > limits.ws_message {
            return Err(format!(
                "[limits] max_ws_frame_bytes = {} is above max_ws_message_bytes = {}: a frame \
                 is at most one message",
                limits.ws_frame, limits.ws_message
            ));
        }
        Ok(limits)
    }

    /// The WebSocket limits for a connection this server dials.
    pub fn ws_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .max_message_size(Some(self.ws_message))
            .max_frame_size(Some(self.ws_frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::bundle::MAX_BUNDLE_BYTES;
    use jig_pipeline::envelope::{Envelope, Frame, ReceiptRef};

    fn b64(n: usize) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(vec![0xA5; n])
    }

    #[test]
    fn unset_limits_are_the_largest_envelope() {
        let limits = Limits::validate(&LimitsSection::default()).unwrap();
        assert_eq!(
            limits,
            Limits {
                request_body: MAX_ENVELOPE_BYTES,
                ws_message: MAX_ENVELOPE_BYTES,
                ws_frame: MAX_ENVELOPE_BYTES,
            }
        );
    }

    /// The default carries the largest block in the largest frame that
    /// carries one: a delivered `Block`, with its signature, receipt and
    /// ingest record, and a submission.
    #[test]
    fn the_largest_block_fits_the_default_limits() {
        let block = Envelope::new(Frame::Block {
            bundle_b64: b64(MAX_BUNDLE_BYTES),
            sig_b64: Some(b64(64)),
            receipts: vec![ReceiptRef {
                server_did: format!("did:jig:z{}", "6".repeat(46)),
                render_hash: Some("ab".repeat(32)),
                receipt_bytes_b64: b64(4096),
            }],
            delivery_cid: format!("b{}", "a".repeat(58)),
            ingest: None,
        });
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: b64(MAX_BUNDLE_BYTES),
            sig_b64: b64(64),
        });
        for frame in [block, submit] {
            let len = serde_json::to_string(&frame).unwrap().len();
            assert!(len <= MAX_ENVELOPE_BYTES, "{len} > {MAX_ENVELOPE_BYTES}");
        }
    }

    #[test]
    fn limits_that_would_refuse_valid_blocks_do_not_boot() {
        for cfg in [
            LimitsSection {
                max_request_body_bytes: Some(MAX_ENVELOPE_BYTES - 1),
                ..Default::default()
            },
            LimitsSection {
                max_ws_message_bytes: Some(1024),
                ..Default::default()
            },
            LimitsSection {
                max_ws_frame_bytes: Some(0),
                ..Default::default()
            },
        ] {
            let err = Limits::validate(&cfg).unwrap_err();
            assert!(err.contains("valid blocks would be refused"), "{err}");
        }
        let err = Limits::validate(&LimitsSection {
            max_ws_frame_bytes: Some(MAX_ENVELOPE_BYTES + 1),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("a frame is at most one message"), "{err}");
    }

    #[test]
    fn the_config_file_sets_them_and_a_typo_is_refused() {
        const ROOT: &str =
            "database_path = \"/tmp/jig.db\"\nbind_address = \"127.0.0.1\"\nport = 7117\n";
        let cfg = crate::config::ServerConfig::from_toml_str(&format!(
            "{ROOT}[limits]\nmax_ws_message_bytes = 6000000\nmax_ws_frame_bytes = 3000000\n"
        ))
        .unwrap();
        let limits = Limits::validate(&cfg.limits).unwrap();
        assert_eq!(
            (limits.request_body, limits.ws_message, limits.ws_frame),
            (MAX_ENVELOPE_BYTES, 6_000_000, 3_000_000)
        );
        let err = crate::config::ServerConfig::from_toml_str(&format!(
            "{ROOT}[limits]\nmax_ws_message = 1\n"
        ))
        .unwrap_err();
        assert!(err.contains("max_ws_message"), "{err}");
    }

    #[test]
    fn raised_limits_are_kept() {
        let raised = MAX_ENVELOPE_BYTES * 2;
        let limits = Limits::validate(&LimitsSection {
            max_request_body_bytes: Some(raised),
            max_ws_message_bytes: Some(raised),
            max_ws_frame_bytes: Some(raised),
        })
        .unwrap();
        assert_eq!(
            (limits.request_body, limits.ws_message, limits.ws_frame),
            (raised, raised, raised)
        );
        let ws = limits.ws_config();
        assert_eq!(
            (ws.max_message_size, ws.max_frame_size),
            (Some(raised), Some(raised))
        );
    }
}
