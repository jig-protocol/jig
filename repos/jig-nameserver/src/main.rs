//! Jig Nameserver binary

use clap::{Parser, Subcommand};
use jig_nameserver::{
    analytics::{AnalyticsEngine, TimeRange},
    config::NameServerConfig,
    server::run_http_server,
    storage::{NamesStorage, SqliteStorage},
};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Database path (env JIG_NS_DB_PATH)
    #[arg(long, global = true)]
    db_path: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the nameserver HTTP server (default)
    Serve {
        /// Bind address (env JIG_NS_BIND)
        #[arg(long)]
        bind: Option<String>,

        /// Port (env JIG_NS_PORT)
        #[arg(long)]
        port: Option<u16>,
    },

    /// Analytics commands
    Analyze {
        #[command(subcommand)]
        analyze_cmd: AnalyzeCommand,
    },

    /// Export analytics data
    Export {
        /// Export format
        #[arg(long, default_value = "json")]
        format: ExportFormat,

        /// Time range
        #[arg(long, default_value = "last_day")]
        range: TimeRangeArg,

        /// Output file (stdout if not specified)
        #[arg(long, short = 'o')]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum AnalyzeCommand {
    /// Analyze receipt statistics
    Receipts {
        /// Time range
        #[arg(long, default_value = "last_day")]
        range: TimeRangeArg,
    },

    /// Analyze anomaly patterns
    Anomalies {
        /// Time range
        #[arg(long, default_value = "last_day")]
        range: TimeRangeArg,
    },

    /// Analyze penalty metrics
    Penalties {
        /// Time range
        #[arg(long, default_value = "last_day")]
        range: TimeRangeArg,
    },

    /// Show comprehensive analytics dashboard
    Dashboard {
        /// Time range
        #[arg(long, default_value = "last_day")]
        range: TimeRangeArg,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum TimeRangeArg {
    LastHour,
    LastDay,
    LastWeek,
    LastMonth,
    /// Last 3 months
    Quarter,
    /// Last 12 months
    Year,
}

impl From<TimeRangeArg> for TimeRange {
    fn from(arg: TimeRangeArg) -> Self {
        match arg {
            TimeRangeArg::LastHour => TimeRange::LastHour,
            TimeRangeArg::LastDay => TimeRange::LastDay,
            TimeRangeArg::LastWeek => TimeRange::LastWeek,
            TimeRangeArg::LastMonth => TimeRange::LastMonth,
            TimeRangeArg::Quarter => TimeRange::Custom {
                start_ts: (chrono::Utc::now() - chrono::Duration::days(90)).timestamp(),
                end_ts: chrono::Utc::now().timestamp(),
            },
            TimeRangeArg::Year => TimeRange::Custom {
                start_ts: (chrono::Utc::now() - chrono::Duration::days(365)).timestamp(),
                end_ts: chrono::Utc::now().timestamp(),
            },
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        // If no command specified, run the server
        None => serve(None, None).await,

        Some(Command::Serve { bind, port }) => serve(bind, port).await,

        Some(Command::Analyze { analyze_cmd }) => {
            handle_analyze(cli.db_path, analyze_cmd).await?;
        }

        Some(Command::Export {
            format,
            range,
            output,
        }) => {
            handle_export(cli.db_path, format, range, output).await?;
        }
    }

    Ok(())
}

/// Start the HTTP server, or exit(1) with an operator-legible reason.
///
/// Startup failures (missing `[pow].server_secret`, a port already in use, an
/// unreadable DB) used to surface as a panic — which reaches stderr through the
/// default panic hook only, so a systemd unit capturing stdout logged nothing
/// but an exit code. Log through BOTH `tracing` and stderr, then exit non-zero.
async fn serve(bind: Option<String>, port: Option<u16>) {
    if let Err(e) = run_http_server(bind, port).await {
        tracing::error!("jig-nameserver failed to start: {e}");
        eprintln!("error: jig-nameserver failed to start: {e}");
        std::process::exit(1);
    }
}

async fn handle_analyze(
    db_path: Option<std::path::PathBuf>,
    cmd: AnalyzeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = NameServerConfig::load()?;
    let db_path = db_path.unwrap_or_else(|| config.storage.database_path.clone());

    let storage = Arc::new(SqliteStorage::new(db_path)?) as Arc<dyn NamesStorage>;
    let engine = AnalyticsEngine::new(storage);

    match cmd {
        AnalyzeCommand::Receipts { range } => {
            let stats = engine.get_receipt_stats(range.into()).await?;
            println!("\n📊 Receipt Statistics\n");
            println!("Total receipts: {}", stats.total_receipts);
            println!("Total fuel used: {}", stats.total_fuel_used);
            println!("Avg fuel per receipt: {:.2}", stats.avg_fuel_per_receipt);
            println!("Success rate: {:.1}%", stats.success_rate * 100.0);

            if !stats.outcome_breakdown.is_empty() {
                println!("\nOutcome Breakdown:");
                for (outcome, count) in &stats.outcome_breakdown {
                    println!("  {outcome}: {count}");
                }
            }

            if !stats.top_hosts.is_empty() {
                println!("\nTop 10 Hosts:");
                for (i, (host, count)) in stats.top_hosts.iter().enumerate().take(10) {
                    println!("  {}. {}: {} receipts", i + 1, host, count);
                }
            }

            if !stats.fuel_by_capability.is_empty() {
                println!("\nFuel by Capability:");
                for (cap, fuel) in &stats.fuel_by_capability {
                    println!("  {cap}: {fuel} fuel");
                }
            }
        }

        AnalyzeCommand::Anomalies { range } => {
            let stats = engine.get_anomaly_stats(range.into()).await?;
            println!("\n⚠️  Anomaly Statistics\n");
            println!("Total anomalies: {}", stats.total_anomalies);
            println!("Escalation rate: {:.1}%", stats.escalation_rate * 100.0);

            if !stats.by_kind.is_empty() {
                println!("\nBy Kind:");
                for (kind, count) in &stats.by_kind {
                    println!("  {kind}: {count}");
                }
            }

            if !stats.by_severity.is_empty() {
                println!("\nBy Severity:");
                for (severity, count) in &stats.by_severity {
                    println!("  {severity}: {count}");
                }
            }

            if !stats.top_offenders.is_empty() {
                println!("\nTop Offenders:");
                for (i, (host, count)) in stats.top_offenders.iter().enumerate().take(10) {
                    println!("  {}. {}: {} anomalies", i + 1, host, count);
                }
            }
        }

        AnalyzeCommand::Penalties { range } => {
            let stats = engine.get_penalty_stats(range.into()).await?;
            println!("\n🚫 Penalty Statistics\n");
            println!("Total penalties applied: {}", stats.total_penalties_applied);
            println!("Active penalties: {}", stats.active_penalties);
            println!("Expired penalties: {}", stats.expired_penalties);
            println!("Total penalty bits: {}", stats.total_penalty_bits);
            println!("Avg penalty bits: {:.2}", stats.avg_penalty_bits);

            if !stats.by_reason.is_empty() {
                println!("\nBy Reason:");
                for (reason, count) in &stats.by_reason {
                    println!("  {reason}: {count}");
                }
            }
        }

        AnalyzeCommand::Dashboard { range } => {
            let dashboard = engine.get_dashboard(range.into()).await?;
            println!("\n📈 Analytics Dashboard - {}\n", dashboard.time_range);

            println!("📊 Receipts:");
            println!("  Total: {}", dashboard.receipts.total_receipts);
            println!(
                "  Success rate: {:.1}%",
                dashboard.receipts.success_rate * 100.0
            );
            println!("  Avg fuel: {:.2}", dashboard.receipts.avg_fuel_per_receipt);

            println!("\n⚠️  Anomalies:");
            println!("  Total: {}", dashboard.anomalies.total_anomalies);
            println!(
                "  Escalation rate: {:.1}%",
                dashboard.anomalies.escalation_rate * 100.0
            );

            println!("\n🚫 Penalties:");
            println!("  Active: {}", dashboard.penalties.active_penalties);
            println!("  Total bits: {}", dashboard.penalties.total_penalty_bits);

            println!("\n💼 Useful Work:");
            println!("  Pending: {}", dashboard.useful_work.pending_work);
            println!(
                "  Completion rate: {:.1}%",
                dashboard.useful_work.completion_rate * 100.0
            );

            println!("\n🔍 Cross-Validation:");
            println!(
                "  Total validations: {}",
                dashboard.cross_validation.total_validations
            );
            println!(
                "  Failure rate: {:.1}%",
                dashboard.cross_validation.failure_rate * 100.0
            );
        }
    }

    Ok(())
}

async fn handle_export(
    db_path: Option<std::path::PathBuf>,
    format: ExportFormat,
    range: TimeRangeArg,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = NameServerConfig::load()?;
    let db_path = db_path.unwrap_or_else(|| config.storage.database_path.clone());

    let storage = Arc::new(SqliteStorage::new(db_path)?) as Arc<dyn NamesStorage>;
    let engine = AnalyticsEngine::new(storage);

    let data = match format {
        ExportFormat::Json => engine.export_json(range.into()).await?,
        ExportFormat::Csv => engine.export_csv(range.into()).await?,
    };

    if let Some(path) = output {
        std::fs::write(&path, data)?;
        println!("Exported to: {}", path.display());
    } else {
        println!("{data}");
    }

    Ok(())
}
