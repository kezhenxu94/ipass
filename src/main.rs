pub mod auth;
pub mod config;
pub mod daemon;
pub mod otp;
pub mod pw;
pub mod srp;
pub mod types;
pub mod util;

use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};

use std::io;

const DEFAULT_PORT: u16 = 27389;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct PassArgs {
    /// Log level
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Args, Debug, Clone)]
pub struct StartArgs {
    /// Port to listen on
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Port to connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Port to connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Website url to list account for
    #[arg()]
    url: String,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    /// Port to connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Website url to get password for
    #[arg()]
    url: String,
    /// User name to get password for
    username: String,
}

#[derive(Args, Debug, Clone)]
pub struct OtpArgs {
    /// Port to connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Website url to get one time password for
    #[arg()]
    url: String,
    /// User name to get one time password for
    username: String,
}

#[derive(Args, Debug, Clone)]
pub struct InstallArgs {
    /// Install the service at user level
    #[arg(long, default_value_t = true)]
    user: bool,
}
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Start the server daemon
    Start(StartArgs),
    /// Authenticate CLI with daemon
    Auth(AuthArgs),
    /// Interact with website passwords
    #[command(subcommand)]
    Pw(PasswordCommands),
    /// Interact with one time passwords (OTP)
    #[command(subcommand)]
    Otp(OtpCommands),
}

#[derive(Subcommand, Debug, Clone)]
enum OtpCommands {
    /// Get one time password by domain and username
    Get(OtpArgs),
}

#[derive(Subcommand, Debug, Clone)]
enum PasswordCommands {
    /// List passwords by domain
    List(ListArgs),
    /// Get password by domain and username
    Get(GetArgs),
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = PassArgs::parse();

    env_logger::builder()
        .filter_level(args.verbose.log_level_filter())
        .format_target(false)
        .format_timestamp(None)
        .init();

    match args.cmd {
        Commands::Start(args) => daemon::start(args).await,
        Commands::Auth(args) => auth::auth(args).await,
        Commands::Pw(commands) => match commands {
            PasswordCommands::List(args) => pw::list(args).await,
            PasswordCommands::Get(args) => pw::get(args).await,
        },
        Commands::Otp(commands) => match commands {
            OtpCommands::Get(args) => otp::get(args).await,
        },
    }
}
