//! `jig channel share` and `unshare` build the blocks the server reads
//! (JEP-0005 rules 7 and 11): the CLI's builders round-trip through the
//! server's own parser, and a server acts on a CLI-built share.

use std::time::Duration;

use integration_tests::harness::*;
use jig_client::blocks::{BuiltBlock, build_channel_share, build_channel_unshare};
use jig_core::contract::Grant;
use jig_core::{BlockKind, BlockManifest, HlcTimestamp};
use jig_pipeline::contracts::{self, ShareRequest};

fn manifest(block: &BuiltBlock) -> BlockManifest {
    serde_json::from_slice(&block.manifest_bytes).expect("a manifest")
}

fn hlc(id: &jig_client::Identity) -> HlcTimestamp {
    HlcTimestamp::now_wall(id.did().clone())
}

#[test]
fn cli_built_shares_read_back_as_the_server_reads_them() {
    let owner = test_identity();
    let to = test_identity().did_string();
    for grant in [Grant::Read, Grant::Write, Grant::Member] {
        let block = build_channel_share(&owner, "#shared", &to, grant, hlc(&owner));
        let m = manifest(&block);
        assert_eq!(m.kind, Some(BlockKind::ChannelShare));
        assert_eq!(
            contracts::share_request(BlockKind::ChannelShare, &m).unwrap(),
            ShareRequest {
                to: to.clone(),
                grant: Some(grant),
            },
        );
        let mut keys: Vec<_> = m.metadata.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            ["channel", "grant", "to"],
            "rule 7's fields, and the channel"
        );
    }

    let block = build_channel_unshare(&owner, "#shared", &to, hlc(&owner));
    let m = manifest(&block);
    assert_eq!(m.kind, Some(BlockKind::ChannelUnshare));
    assert_eq!(
        contracts::share_request(BlockKind::ChannelUnshare, &m).unwrap(),
        ShareRequest {
            to: to.clone(),
            grant: None,
        },
    );
}

/// A share the owner submits lands, and the server acts on it: a target that
/// is not one of its peers is refused in the channel's log (`NOT_A_PEER`),
/// which it can only write after reading the share's `to`.
#[tokio::test]
async fn a_server_acts_on_a_cli_built_share() {
    // The default config: its block kinds include channel-share and the
    // contract records, which the harness's narrower list leaves out.
    let config = jig_config::v0_0_2_server::JigServerConfig::default();
    let server = TestJigServer::start_with_config(config)
        .await
        .expect("start");
    let _contracts = jig_server::v0_0_2_contract::start(&server.state);

    let owner = test_identity();
    let channel = server
        .create_channel(&owner, "#shared", "open")
        .await
        .expect("create");
    let stranger = test_identity().did_string();
    server
        .submit_block(&build_channel_share(
            &owner,
            "#shared",
            &stranger,
            Grant::Read,
            hlc(&owner),
        ))
        .await
        .expect("the owner may share");

    let store = &server.state.ingest_ctx.store;
    let mut refused = None;
    for _ in 0..100 {
        refused = store
            .list_ingest_records_by_id(&channel, 0, 100)
            .unwrap()
            .iter()
            .filter_map(|r| store.get_block(&r.block_cid).unwrap())
            .find(|b| b.block_kind == BlockKind::ContractRefuse.as_str());
        if refused.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let refused = refused.expect("a contract-refuse in the channel's log");
    let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&refused.bundle_bytes).unwrap();
    let m: BlockManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(m.metadata["to"], stranger);
    assert_eq!(m.metadata["code"], "NOT_A_PEER");

    // Someone without the share right is refused by the server, with its
    // code: the CLI does not check first.
    let other = test_identity();
    let err = server
        .submit_block(&build_channel_share(
            &other,
            "#shared",
            &stranger,
            Grant::Read,
            hlc(&other),
        ))
        .await
        .expect_err("only the owner or an admin may share");
    assert!(err.to_string().contains("share"), "{err:#}");
}
