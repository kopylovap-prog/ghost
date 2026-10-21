//! Ghost CLI

use clap::{Parser, Subcommand};
use opacus_crypto::keys::SpendingKey;
use opacus_miner::{MinerConfig, MinerEngine, MiningMode};
use opacus_node::{DaemonConfig, OpacusDaemon};
use opacus_wallet::LightWallet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "ghost", version, about = "Ghost: Private. Instant. Bridgeable.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start full node
    Start {
        #[arg(long)]
        tor: bool,
    },
    /// Mine Ghost
    Mine {
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        solo: bool,
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
    },
    /// Create new wallet
    CreateWallet,
    /// Restore wallet from seed
    RestoreWallet {
        #[arg(short, long)]
        seed: String,
    },
    /// Show address
    Address,
    /// Show balance
    Balance,
    /// Send (requires node)
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        amount: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Start { tor } => start_node(tor).await?,
        Commands::Mine { pool, address, threads, solo, duration_secs } => {
            run_miner(pool, address, threads, solo, duration_secs).await?
        }
        Commands::CreateWallet => create_wallet()?,
        Commands::RestoreWallet { seed } => restore_wallet(&seed)?,
        Commands::Address => show_address()?,
        Commands::Balance => show_balance()?,
        Commands::Send { to, amount } => send(&to, amount)?,
    }
    Ok(())
}

async fn start_node(tor: bool) -> anyhow::Result<()> {
    println!("Starting Ghost Node... (Ctrl+C to stop)");
    let config = DaemonConfig { use_tor: tor, ..Default::default() };
    let mut daemon = OpacusDaemon::new(config)?;
    daemon.run().await?;
    Ok(())
}

async fn run_miner(
    pool: Option<String>,
    address: Option<String>,
    threads: Option<usize>,
    solo: bool,
    duration_secs: u64,
) -> anyhow::Result<()> {
    let mut config = MinerConfig::default();
    config.mode = if solo { MiningMode::Solo } else { MiningMode::Pool };
    if let Some(p) = pool {
        config.pool_url = Some(p);
    }
    config.reward_address = match address {
        Some(a) => a,
        None => {
            let dir = wallet_dir()?;
            let path = dir.join("mnemonic.txt");
            if path.exists() {
                let mnemonic = std::fs::read_to_string(&path)?;
                let key = SpendingKey::from_mnemonic(mnemonic.trim())?;
                LightWallet::new(&key).get_address().to_string()
            } else {
                println!("WARNING: no wallet found - empty address. Run: ghost create-wallet");
                String::new()
            }
        }
    };
    config.threads = threads;

    println!("Ghost Miner");
    println!("  Mode:     {:?}", config.mode);
    println!("  Threads:  {}", config.effective_threads());
    println!(
        "  Address:  {}",
        if config.reward_address.is_empty() { "(not set)" } else { &config.reward_address }
    );
    println!("  Duration: {}s (Ctrl+C to stop early)", duration_secs);
    println!();

    let engine = MinerEngine::new(config);
    let stop_flag = engine.stop_flag();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!();
            println!("Stopping...");
            stop_flag.store(true, Ordering::Relaxed);
        }
    });

    tokio::task::spawn_blocking(move || {
        engine.run_blocking(Some(Duration::from_secs(duration_secs)))
    })
    .await
    .map_err(|e| anyhow::anyhow!("task error: {e}"))??;

    println!();
    println!("Mining session complete!");
    Ok(())
}

fn create_wallet() -> anyhow::Result<()> {
    use rand::rngs::OsRng;
    let key = SpendingKey::generate(&mut OsRng);

    let dir = wallet_dir()?;
    std::fs::create_dir_all(&dir)?;

    let mnemonic_path = dir.join("mnemonic.txt");
    std::fs::write(&mnemonic_path, &key.mnemonic)?;

    let wallet = LightWallet::new(&key);
    std::fs::write(dir.join("address.txt"), wallet.get_address())?;

    println!("Wallet created!");
    println!();
    println!("SEED PHRASE (keep it safe!):");
    println!("=============================================");
    println!("{}", key.mnemonic);
    println!("=============================================");
    println!();
    println!("WARNING: anyone with this phrase can steal your funds!");
    println!("Address: {}", wallet.get_address());
    println!("Wallet:  {}", dir.display());
    Ok(())
}

fn restore_wallet(seed: &str) -> anyhow::Result<()> {
    let key = SpendingKey::from_mnemonic(seed)?;
    let wallet = LightWallet::new(&key);

    let dir = wallet_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("mnemonic.txt"), seed)?;
    std::fs::write(dir.join("address.txt"), wallet.get_address())?;

    println!("Wallet restored!");
    println!("Address: {}", wallet.get_address());
    Ok(())
}

fn show_address() -> anyhow::Result<()> {
    let path = wallet_dir()?.join("address.txt");
    if path.exists() {
        println!("Address: {}", std::fs::read_to_string(&path)?.trim());
    } else {
        println!("No wallet found. Run: ghost create-wallet");
    }
    Ok(())
}

fn show_balance() -> anyhow::Result<()> {
    println!("Balance: 0.000000000 GHOST");
    println!("  (node connection in v0.3)");
    Ok(())
}

fn send(to: &str, amount: u64) -> anyhow::Result<()> {
    println!("Sending {} atoms to {} ...", amount, to);
    println!("  (send via node in v0.3)");
    Ok(())
}

fn wallet_dir() -> anyhow::Result<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("no home dir"))?
        .join(".ghost")
        .join("wallet"))
}