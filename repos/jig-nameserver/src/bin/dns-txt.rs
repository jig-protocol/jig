//! CLI tool to generate DNS TXT records for nameserver capabilities

use jig_nameserver::NameServerConfig;

fn main() {
    let cfg = NameServerConfig::load().expect("failed to load config");

    println!("# DNS TXT Records for Jig Nameserver Capabilities");
    println!("# Add these records to your DNS zone:\n");

    let domain = cfg
        .capabilities
        .domain
        .as_deref()
        .unwrap_or("_jig-ns.example.com");

    for (i, record) in cfg.capabilities.to_dns_txt_records().iter().enumerate() {
        println!("{domain}  IN  TXT  \"{record}\"");
        if i == 0 {
            println!("# Or with record numbering:");
            println!("{domain}  IN  TXT  \"{record}\"");
        }
    }

    println!("\n# Alternative: Single multi-value TXT record");
    println!("{domain}  IN  TXT  \\");
    for (i, record) in cfg.capabilities.to_dns_txt_records().iter().enumerate() {
        let is_last = i == cfg.capabilities.to_dns_txt_records().len() - 1;
        println!("    \"{}\"{}", record, if is_last { "" } else { " \\" });
    }

    println!("\n# Verification:");
    println!("# dig TXT {domain} +short");
}
