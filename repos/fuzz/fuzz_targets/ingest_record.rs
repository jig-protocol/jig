//! `IngestRecord::decode`: the sequencer's signed record of a block's place
//! in its channel, which a follower takes from the owner (JEP-0005 rules
//! 12-14) and stores as it arrived. And `IngestRecord::from_cose`: the same
//! record from its envelope alone, as a block's `seen` and a `head` frame
//! carry it from anyone (JEP-0002 rule 10).
#![no_main]

use jig_pipeline::ingest_record::IngestRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = IngestRecord::from_cose(data) {
        let _ = record.payload();
        let _ = record.verify(&record.sequencer);
        // The envelope is kept as it came, so the record hashes as it did.
        assert_eq!(record.cose_bytes().expect("kept as base64"), data);
        let again = IngestRecord::from_cose(data).expect("the same bytes parse again");
        assert_eq!(again, record);
    }
    let Ok(record) = IngestRecord::decode(data) else {
        return;
    };
    let _ = record.payload();
    let _ = record.hash();
    let _ = record.is_genesis();
    let _ = record.verify(&record.sequencer);
    let again = IngestRecord::decode(&record.encode()).expect("an encoded record decodes");
    assert_eq!(again, record);
});
