//! `IngestRecord::decode`: the sequencer's signed record of a block's place
//! in its channel, which a follower takes from the owner (JEP-0005 rules
//! 12-14) and stores as it arrived.
#![no_main]

use jig_pipeline::ingest_record::IngestRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
