use jig_core::BlockManifest;

#[test]
fn schema_v0_1_parses_correctly() {
    let v0_1_json = include_str!("fixtures/manifest_v0.1.json");
    let manifest: BlockManifest = serde_json::from_str(v0_1_json).unwrap();

    assert_eq!(
        manifest.schema,
        "https://jig.dev/schema/block-manifest/v0.1"
    );
    assert_eq!(manifest.version.to_string(), "0.1.0");
    assert_eq!(manifest.authors.len(), 1);
    assert_eq!(manifest.authors[0].did, "did:jig:alice123");
}

#[test]
fn schema_v0_1_validates() {
    let v0_1_json = include_str!("fixtures/manifest_v0.1.json");
    let manifest: BlockManifest = serde_json::from_str(v0_1_json).unwrap();

    // Should pass validation
    assert!(manifest.validate().is_ok());
}

#[test]
fn schema_v0_1_computes_cid() {
    let v0_1_json = include_str!("fixtures/manifest_v0.1.json");
    let manifest: BlockManifest = serde_json::from_str(v0_1_json).unwrap();

    let manifest_bytes = manifest.to_canonical_bytes().unwrap();
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &[],
        resources: vec![],
    };

    // Should compute CID successfully
    let cid = bundle.block_cid();
    assert!(cid.is_ok());
}

#[test]
fn schema_v0_1_can_build_receipt() {
    let v0_1_json = include_str!("fixtures/manifest_v0.1.json");
    let manifest: BlockManifest = serde_json::from_str(v0_1_json).unwrap();

    let manifest_bytes = manifest.to_canonical_bytes().unwrap();
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &[],
        resources: vec![],
    };
    let block_id = bundle.block_cid().unwrap();

    // Should be able to build receipt
    let receipt = jig_core::BlockReceipt::builder(block_id)
        .render_hash("abc123")
        .fuel_used(100_000)
        .host("did:jig:host")
        .capability("core:compute")
        .build();

    assert!(receipt.is_ok());
}

#[test]
fn schema_v0_1_receipts_validate_against_manifest() {
    let v0_1_json = include_str!("fixtures/manifest_v0.1.json");
    let manifest: BlockManifest = serde_json::from_str(v0_1_json).unwrap();

    let manifest_bytes = manifest.to_canonical_bytes().unwrap();
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &[],
        resources: vec![],
    };
    let block_id = bundle.block_cid().unwrap();

    let receipt = jig_core::BlockReceipt::builder(block_id)
        .render_hash("abc123")
        .fuel_used(100_000)
        .host("did:jig:host")
        .capability("core:compute")
        .build()
        .unwrap();

    // Receipt should validate against manifest
    assert!(receipt.validate_against_manifest(&manifest).is_ok());
}
