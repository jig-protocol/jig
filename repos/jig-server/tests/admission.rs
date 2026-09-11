//! Gate 2: a server may refuse a caller before asking what they want.
//!
//! Every request here carries a genuine proof, so gate 1 passes and the
//! refusal is admission's — the convention that a refusal test proves nothing
//! if it fails at the wrong gate.

use axum::http::StatusCode;
use jig_config::v0_0_2_server::{
    AdmissionFloor, AdmissionSection, ReputationRecord, UnknownDidsPolicy,
};

mod support;
use support::ws::WsClient;
use support::{Identity, TestServer, history_path};

fn banning(who: &Identity) -> AdmissionSection {
    AdmissionSection {
        banned_dids: vec![who.did().to_did_jig_string()],
        ..AdmissionSection::default()
    }
}

fn record(who: &Identity, ruleset: &str, score: i64) -> ReputationRecord {
    ReputationRecord {
        did: who.did().to_did_jig_string(),
        ruleset_key: ruleset.to_string(),
        score,
    }
}

#[tokio::test]
async fn a_banned_did_is_refused_on_every_read_surface() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    for path in [
        "/api/v1/channels".to_string(),
        history_path("#open"),
        "/api/v1/blocks/bafy_anything".to_string(),
    ] {
        let (status, body) = server.send(&server.sign_get(&banned, &path)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: body={body}");
        assert_eq!(body["code"], "NOT_ADMITTED", "{path}");
    }

    // And the same key is fine on a server that has not banned it.
    let open_server = TestServer::authenticated();
    let (status, _) = open_server
        .send(&open_server.sign_get(&banned, "/api/v1/channels"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the ban is this server's, not the key's"
    );
}

/// THE ordering test. Admission runs before authorization, so a banned DID
/// asking about a restricted channel it is not a member of is told
/// NOT_ADMITTED — never NOT_A_MEMBER, which would confirm the channel exists.
#[tokio::test]
async fn admission_is_decided_before_authorization() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&banned, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED", "not NOT_A_MEMBER: {body}");

    // Nor is an unknown slug read back as an empty 200 to a refused caller.
    let (status, body) = server
        .send(&server.sign_get(&banned, &history_path("#nowhere")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

#[tokio::test]
async fn a_banned_did_cannot_subscribe() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    let url = server.serve_ws().await;
    let mut ws = WsClient::connect(&url).await;
    match ws.subscribe(&banned, "#open").await {
        Some(jig_pipeline::Frame::Error { status, code, .. }) => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_ADMITTED");
        }
        other => panic!("expected a 403 error frame, got {other:?}"),
    }
}

/// `unknown_dids = "refuse"` with seeded records is a members-only server:
/// the seeded key reads, a fresh key does not.
#[tokio::test]
async fn a_members_only_server_admits_seeded_dids_and_refuses_strangers() {
    let owner = Identity::new(1);
    let member = Identity::new(2);
    let stranger = Identity::new(3);
    let server = TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::Refuse,
        records: vec![record(&owner, "club", 1), record(&member, "club", 1)],
        ..AdmissionSection::default()
    });
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server
        .send(&server.sign_get(&member, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::OK, "member: {body}");

    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "stranger: {body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// A floor refuses a scored-below DID and must NOT refuse a DID with no
/// score under its ruleset while unknowns are admitted.
#[tokio::test]
async fn a_floor_refuses_low_scores_and_leaves_unknowns_to_the_unknown_choice() {
    let owner = Identity::new(1);
    let low = Identity::new(2);
    let unscored = Identity::new(3);
    let server = TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::Admit,
        floors: vec![AdmissionFloor {
            ruleset_key: "club".to_string(),
            minimum: 0,
        }],
        records: vec![record(&low, "club", -5)],
        ..AdmissionSection::default()
    });
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server
        .send(&server.sign_get(&low, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "low: {body}");
    assert_eq!(body["code"], "NOT_ADMITTED");

    let (status, body) = server
        .send(&server.sign_get(&unscored, &history_path("#open")))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unscored must not be compared against the floor: {body}"
    );
}

/// The read escape hatch is about READS: with no proof there is nobody to
/// admit, so gate 2 is skipped there along with the rest. Writes always
/// carry a signature, so admission still applies to them — the hatch does
/// not turn a members-only server into an open letterbox.
#[tokio::test]
async fn the_read_escape_hatch_skips_admission_for_reads_only() {
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
    config.auth.require_authenticated_reads = false;
    config.auth.admission.unknown_dids = UnknownDidsPolicy::Refuse;
    config.auth.admission.records = vec![record(&owner, "club", 1)];
    let server = TestServer::with_full_config(config);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server.send_unsigned(&history_path("#open")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unsigned read under the hatch: {body}"
    );

    let me = stranger.as_client();
    let block = build_text_render(&me, "#open", "hi", HlcTimestamp::now_wall(me.did().clone()));
    let (status, body) = server.try_submit(&block).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stranger's write is still refused: {body}"
    );
    assert_eq!(body["code"], "NOT_ADMITTED");
}

// ---- Writes ------------------------------------------------------------------
//
// "Blocks authenticating their own request … need to be refusable based on
// server preference." Admission runs inside ingest, so every write surface
// gets it: the public submit, WSS Submit, and the admin channel routes.

use jig_client::blocks::{build_channel_create, build_text_render};
use jig_core::HlcTimestamp;

#[tokio::test]
async fn a_banned_did_cannot_post_over_rest() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    let me = banned.as_client();
    let block = build_text_render(&me, "#open", "hi", HlcTimestamp::now_wall(me.did().clone()));
    let (status, body) = server.try_submit(&block).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED");

    // Nothing landed.
    let (_, timeline) = server
        .send(&server.sign_get(&owner, &history_path("#open")))
        .await;
    assert_eq!(
        timeline.as_array().map_or(0, Vec::len),
        1,
        "only the channel-create block: {timeline}"
    );
}

#[tokio::test]
async fn a_banned_did_cannot_post_over_wss() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    let url = server.serve_ws().await;
    let mut ws = WsClient::connect(&url).await;
    match ws.submit_text(&banned, "#open", "hi").await {
        jig_pipeline::Frame::Error { status, code, .. } => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_ADMITTED");
        }
        other => panic!("expected an error frame, got {other:?}"),
    }
}

/// The admin routes are a write surface like any other. A refused key
/// cannot create a channel — and admission precedes ownership, so a banned
/// OWNER cannot even archive their own.
#[tokio::test]
async fn a_banned_did_cannot_use_the_admin_routes_even_as_an_owner() {
    let owner = Identity::new(1);
    let server = TestServer::with_admission(banning(&owner));

    let me = owner.as_client();
    let create = build_channel_create(
        &me,
        "#mine",
        "open",
        HlcTimestamp::now_wall(me.did().clone()),
    );
    let (status, body) = server.try_submit(&create).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "create: {body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// Admission is decided on the DID the signature ESTABLISHED, not on the
/// spelling in the manifest: a banned key cannot slip past its ban by
/// re-casing its DID.
#[tokio::test]
async fn a_recased_author_did_is_still_the_banned_key() {
    use jig_core::{Author, BlockKind, BlockManifest};
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    let me = banned.as_client();
    let did_string = me.did_string();
    let (prefix, body) = did_string.split_at("did:jig:z".len());
    let recased = jig_core::Did::from_str_unchecked(format!("{prefix}{}", body.to_uppercase()));
    let manifest = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: recased,
            public_key: None,
            roles: vec![],
        })
        .metadata_entry("channel", serde_json::json!("#open"))
        .metadata_entry("body", serde_json::json!("hi"))
        .build()
        .unwrap()
        .with_kind(BlockKind::TextRender)
        .with_hlc(HlcTimestamp::now_wall(me.did().clone()));
    let manifest_bytes = manifest.to_canonical_bytes().unwrap();
    let payload = serde_json::to_vec(&(manifest_bytes.clone(), Vec::<u8>::new())).unwrap();
    let block = jig_client::blocks::BuiltBlock {
        manifest_bytes,
        code_bytes: vec![],
        sender_sig: me.sign(&payload).to_bytes().to_vec(),
    };

    let (status, body) = server.try_submit(&block).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// Found in review: the admin archive route looked the channel up — and named
/// its owner — before `ingest` verified anything. A refused caller (here:
/// banned, but the pre-check ran before the signature too) must get one
/// answer whatever they ask, and never the owner's DID.
#[tokio::test]
async fn the_archive_route_is_not_an_existence_or_owner_oracle() {
    use jig_client::blocks::build_channel_archive;
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#board", "open").await;

    let me = banned.as_client();
    for slug in ["#board", "#nowhere"] {
        let block = build_channel_archive(&me, slug, HlcTimestamp::now_wall(me.did().clone()));
        let (status, body) = server.try_archive(slug, &block).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{slug}: {body}");
        assert_eq!(body["code"], "NOT_ADMITTED", "{slug}: {body}");
        assert!(
            !body.to_string().contains(&owner.did().to_did_jig_string()),
            "{slug}: the owner's DID must not appear: {body}"
        );
    }
}

/// And with NO valid signature at all — the route used to answer before
/// checking one. An unsigned archive attempt gets INVALID_SIG for an
/// existing and a nonexistent channel alike.
#[tokio::test]
async fn the_archive_route_verifies_the_signature_before_answering_anything() {
    use jig_client::blocks::build_channel_archive;
    let owner = Identity::new(1);
    let forger = Identity::new(2);
    let server = TestServer::authenticated();
    server.create_channel(&owner, "#board", "open").await;

    let me = forger.as_client();
    for slug in ["#board", "#nowhere"] {
        let mut block = build_channel_archive(&me, slug, HlcTimestamp::now_wall(me.did().clone()));
        block.sender_sig[0] ^= 0xff; // no longer a valid signature
        let (status, body) = server.try_archive(slug, &block).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{slug}: {body}");
        assert_eq!(body["code"], "INVALID_SIG", "{slug}: {body}");
    }
}
