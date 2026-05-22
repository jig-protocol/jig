//! Configuration Generator CLI Tool
//!
//! This example demonstrates how to use the template generator to create
//! configuration files for different profiles.
//!
//! ## Usage
//!
//! ```bash
//! # Generate minimal potato config
//! cargo run --example config_generator -- --profile potato
//!
//! # Generate full standard config
//! cargo run --example config_generator -- --profile standard --full
//!
//! # Generate config without comments
//! cargo run --example config_generator -- --profile hyperscale --full --no-comments
//!
//! # Save to file
//! cargo run --example config_generator -- --profile potato --full > potato.toml
//! ```

use jig_config::{profiles::Profile, templates::TemplateGenerator};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut profile = Profile::Potato;
    let mut full = false;
    let mut include_comments = true;
    let mut include_examples = false;

    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" | "-p" => {
                if i + 1 < args.len() {
                    profile = match args[i + 1].to_lowercase().as_str() {
                        "potato" => Profile::Potato,
                        "standard" => Profile::Standard,
                        "hyperscale" => Profile::Hyperscale,
                        "custom" => Profile::Custom,
                        _ => {
                            eprintln!("Unknown profile: {}", args[i + 1]);
                            eprintln!("Valid profiles: potato, standard, hyperscale, custom");
                            std::process::exit(1);
                        }
                    };
                    i += 1;
                }
            }
            "--full" | "-f" => {
                full = true;
            }
            "--no-comments" => {
                include_comments = false;
            }
            "--examples" | "-e" => {
                include_examples = true;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Generate template
    let template = TemplateGenerator::new()
        .profile(profile)
        .full(full)
        .include_comments(include_comments)
        .include_examples(include_examples)
        .generate();

    // Output template
    println!("{template}");

    // Print guidance to stderr
    if full {
        eprintln!(
            "\n# Generated full {} configuration",
            profile.to_string().to_lowercase()
        );
    } else {
        eprintln!(
            "\n# Generated minimal {} configuration",
            profile.to_string().to_lowercase()
        );
        eprintln!("# For full configuration, use: --full");
    }

    eprintln!(
        "# Save to file: cargo run --example config_generator -- --profile {} {} > config.toml",
        profile.to_string().to_lowercase(),
        if full { "--full" } else { "" }
    );
}

fn print_help() {
    eprintln!("Configuration Generator - Generate jig-config TOML templates\n");
    eprintln!("USAGE:");
    eprintln!("    config_generator [OPTIONS]\n");
    eprintln!("OPTIONS:");
    eprintln!(
        "    -p, --profile <PROFILE>    Profile to generate (potato, standard, hyperscale, custom)"
    );
    eprintln!("                                Default: potato");
    eprintln!("    -f, --full                  Generate full configuration with all sections");
    eprintln!("    --no-comments              Generate without explanatory comments");
    eprintln!("    -e, --examples             Include example values");
    eprintln!("    -h, --help                  Print this help message\n");
    eprintln!("EXAMPLES:");
    eprintln!("    # Generate minimal potato config");
    eprintln!("    cargo run --example config_generator -- --profile potato\n");
    eprintln!("    # Generate full standard config with examples");
    eprintln!("    cargo run --example config_generator -- --profile standard --full --examples\n");
    eprintln!("    # Save hyperscale config to file");
    eprintln!(
        "    cargo run --example config_generator -- --profile hyperscale --full > hyperscale.toml"
    );
}
