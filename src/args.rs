use std::time::Duration;
use duration_string::DurationString;
use clap::{Args, Parser};
use ethers::prelude::*;
use strum::EnumString;
use url::Url;

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
    #[command(about = "Transfer ETH")]
    Transfer(TransferArgs),
    #[command(about = "Swap ETH on Uniswap DEX")]
    Uniswap(UniswapArgs),
    #[command(about = "Buy NFT on Opensea")]
    BuyNft(BuyNFTArgs)
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
pub struct VTCArgs {
    #[clap(short = 'v', long = "vtc-method", default_value = "tlock", help = "VTC method ('htlp', 'tlock')")]
    pub method: VTCMethod,

    #[clap(
    long,
    default_value = "18",
    help = "HTLP hardness parameter"
    )]
    pub htlp_hardness: u64,

    #[clap(long, default_value = "https://pl-us.testnet.drand.sh", help = "drand network host url")]
    pub drand_network: String,

    #[clap(long, default_value = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf", help = "drand chain hash")]
    pub chain_hash: String,

    #[clap(short, long, default_value = "360s", help = "lock file for duration (y/w/d/h/m/s/ms)")]
    pub refund_duration: humantime::Duration,
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

    #[clap(flatten)]
    pub vtc: VTCArgs,

    #[clap(
        short = 'a',
        default_value = "127.0.0.1:8000",
        long,
        help = "server address"
    )]
    pub server_address: String,
}

#[derive(Clone, Args)]
pub struct TransferArgs {
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

    #[clap(short = 'a', long, help = "market maker server address")]
    pub relay_address: String,

    #[clap(flatten)]
    pub vtc: VTCArgs,

    #[clap(short = 'd', long, help = "ask Maker to withdraw after the delay")]
    pub withdraw_delay: Option<humantime::Duration>,

    #[clap(index = 1, help = "target address (to)")]
    pub target_address: String,

    #[clap(index = 2, help = "transfer amount (ETH)")]
    pub amount: f64,
}


#[derive(Clone, Args)]
pub struct UniswapArgs {
    #[clap(flatten)]
    pub base_args: TransferArgs,

    #[clap(index = 3, default_value = "USDC", help = "target ERC20")]
    pub target_erc20: String,
}


#[derive(Clone, Args)]
pub struct BuyNFTArgs {
    #[clap(flatten)]
    pub base_args: TransferArgs,

    #[clap(short= 'c', long, help = "The NFT address you want to buy")]
    pub nft_contract: Address,

    #[clap(short = 'i', long, help = "The NFT id you want to buy")]
    pub token_id: U256,
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

#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum VTCMethod {
    #[strum(serialize = "htlp")]
    HTLP,
    #[strum(serialize = "tlock")]
    TLock
}
