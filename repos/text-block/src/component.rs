//! The `jig:block/renderer@0.1.0` export (JEP-0006).
//!
//! Built only with `--features component`, so host builds of this crate don't compile
//! `wit-bindgen`. The component's core module exposes nothing but what `wit-bindgen` generates.
//!
//! The body of the invocation's input is the raw message text. The returned payload is the
//! postcard-encoded [`crate::Output`], under [`COMPONENT_OUTPUT_MEDIA_TYPE`]. `render_hash` inside it is unchanged: it is still
//! `blake3(canonical_text)`, computed by [`execute_pure`].

use crate::canonical::COMPONENT_OUTPUT_MEDIA_TYPE;
use crate::{Input, execute_pure};

wit_bindgen::generate!({
    world: "renderer",
    path: "../jig-spec/wit/jig-block",
});

use exports::jig::block::render::Guest;
use jig::block::types::{BlockError, Invocation, Payload};

struct TextBlock;

impl Guest for TextBlock {
    fn render(inv: Invocation) -> Result<Payload, BlockError> {
        let body_raw = String::from_utf8(inv.input.body)
            .map_err(|_| BlockError::InvalidInput("message body is not UTF-8".into()))?;
        let input = Input {
            sender_did: inv.sender_did,
            channel_id: inv.channel_cid,
            body_raw,
            hlc_wall_ms: inv.ingest_hlc.wall_ms,
            hlc_logical: inv.ingest_hlc.logical,
            // The ingest record is the clock (L7); its signer and the client version are not
            // inputs to the render.
            hlc_origin: String::new(),
            client_version: String::new(),
        };
        let body = postcard::to_allocvec(&execute_pure(&input))
            .map_err(|_| BlockError::Failed("output did not encode".into()))?;
        Ok(Payload {
            media_type: COMPONENT_OUTPUT_MEDIA_TYPE.into(),
            body,
        })
    }
}

export!(TextBlock);
