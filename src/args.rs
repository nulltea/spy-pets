use clap::{Args, Parser};
use strum::EnumString;
use url::Url;

pub const NETWORK_FEE_DELTA: f64 = 0.1;

#[derive(Clone, Parser)]
pub struct Options {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, clap::Subcommand)]
pub enum Command {
    #[command(about = "Setup wallet")]
    Setup(SetupArgs),
    #[command(about = "Deploy provider daemon")]
    Provide(ProvideArgs),
    #[command(about = "Run swap client")]
    Swap(SwapArgs),
}

#[derive(Clone, Args)]
pub struct SetupArgs {
    #[clap(
        short,
        long,
        default_value = "./keys",
        help = "path to keystore location"
    )]
    pub keystore_dir: String,
}

#[derive(Clone, Args)]
pub struct ProvideArgs {
    #[clap(
        short,
        long,
        default_value = "./keys",
        help = "path to keystore location"
    )]
    pub keystore_dir: String,

    #[clap(short, long, help = "wallet name")]
    pub wallet_name: Option<String>,

    #[clap(short, long, help = "wallet password")]
    pub password: Option<String>,

    #[clap(short, long, default_value = "development", help = "Ethereum network")]
    pub network: Network,

    #[clap(short, long, help = "secondary address (to)")]
    pub secondary_address: String,

    #[clap(
        short,
        long,
        default_value = "18",
        help = "time parameter of the VTC scheme"
    )]
    pub time_lock_param: u64,

    #[clap(
        short = 'a',
        default_value = "127.0.0.1:8000",
        long,
        help = "server address"
    )]
    pub server_address: String,
}

#[derive(Clone, Args)]
pub struct SwapArgs {
    #[clap(
        short,
        long,
        default_value = "./keys",
        help = "path to keystore location"
    )]
    pub keystore_dir: String,

    #[clap(short, long, help = "wallet name")]
    pub wallet_name: Option<String>,

    #[clap(short, long, help = "wallet password")]
    pub password: Option<String>,

    #[clap(short, long, default_value = "development", help = "Ethereum network")]
    pub network: Network,

    #[clap(short, long, help = "market maker server address")]
    pub relay_address: String,

    #[clap(short, long, help = "transfer amount (ETH)")]
    pub amount: f64,

    #[clap(
        short,
        long,
        default_value = "18",
        help = "time parameter of the VTC scheme"
    )]
    pub time_lock_param: u64,

    #[clap(index = 1, help = "target address (to)")]
    pub target_address: String,
}

#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum Network {
    #[strum(serialize = "mainnet")]
    Mainnet,
    #[strum(serialize = "goerli")]
    Goerli,
    #[strum(serialize = "development")]
    Development,
}

impl Network {
    pub fn get_endpoint(&self) -> Url {
        match self {
            Network::Mainnet => {
                Url::parse("https://mainnet.infura.io/v3/c60b0bb42f8a4c6481ecd229eddaca27").unwrap()
            }
            Network::Goerli => {
                Url::parse("https://goerli.infura.io/v3/c60b0bb42f8a4c6481ecd229eddaca27").unwrap()
            }
            Network::Development => Url::parse("http://localhost:8545").unwrap(),
        }
    }

    pub fn get_chainid(&self) -> String {
        match self {
            Network::Mainnet => "1".to_string(),
            Network::Goerli => "420".to_string(),
            Network::Development => "31337".to_string(),
        }
    }
}
