#[macro_use]
extern crate rocket;

use std::process;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use anyhow::anyhow;
use async_std::task::spawn;
use curv::arithmetic::Converter;
use ethers::prelude::*;
use futures::channel::oneshot;
use futures::SinkExt;
use gumdrop::Options;
use url::Url;
use crate::args::CLIArgs;
use crate::ethereum::{Ethereum, WEI_IN_ETHER};
use crate::maker::Maker;
use crate::taker::Taker;
use crate::args::*;

mod maker;
mod taker;
mod ethereum;
mod utils;
mod server;
mod client;
mod args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // pretty_env_logger::init();

    let args: CLIArgs = CLIArgs::parse_args_default_or_exit();
    let command = args.command.unwrap_or_else(|| {
        eprintln!("[command] is required");
        eprintln!("{}", CLIArgs::usage());
        process::exit(2)
    });

    match command {
        Command::Setup(args) => setup(args).await?,
        Command::Provide(args) => provide(args).await?,
        Command::Swap(args) => swap(args).await?,
    }

    Ok(())
}

async fn setup(args: SetupArgs) -> anyhow::Result<()> {

    Ok(())
}

async fn provide(args: ProvideArgs) -> anyhow::Result<()> {
    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await?;
    let wallet = LocalWallet::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();

    let target_address = Address::from_str(&args.target_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let (alice, mut to_alice) = Maker::new(eth_provider.clone(), wallet, target_address).unwrap();

    tokio::spawn(async {
        alice.run().await;
    });

    server::serve(to_alice).await;

    Ok(())
}

async fn swap(args: SwapArgs) -> anyhow::Result<()> {
    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await?;
    let wallet = LocalWallet::from_str("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d").unwrap();

    let target_address = Address::from_str(&args.target_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;

    let client = client::Client::new(args.maker_address)?;

    let mut bob = Taker::new(eth_provider.clone(), wallet, target_address, args.amount);
    let setup_msg = bob.setup1()?;

    let alice_setup_msg = client.setup(setup_msg).await?;

    let lock_msg1 = bob.setup2(alice_setup_msg).await?;

    let alice_lock_msg = client.lock(args.amount, lock_msg1).await?;

    let lock_msg2 = bob.lock(alice_lock_msg)?;

    let alice_swap_msg = client.swap(lock_msg2).await?;
    let _ = bob.complete(alice_swap_msg).await?;

    let wei = eth_provider.provider.get_balance(Address::from_str(&args.target_address).unwrap(), None).await.unwrap();
    let eth = wei / WEI_IN_ETHER;
    println!("balance of {} is {} ETH", args.target_address, eth.as_u64());

    Ok(())
}
