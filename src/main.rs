#[macro_use]
extern crate rocket;

use std::path::Path;
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
use inquire::{Password, Select, Text};
use url::Url;
use crate::args::CLIArgs;
use crate::ethereum::{Ethereum, WEI_IN_ETHER};
use crate::maker::Maker;
use crate::taker::Taker;
use crate::args::*;
use crate::utils::{keypair_from_bip39, keypair_from_hex, keypair_gen, read_from_keystore, write_to_keystore};

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
    let options = vec![
        "Generate new",
        "Recover from hex",
        "Recover from BIP39 mnemonic",
    ];
    let picked = Select::new("Wallet source?", options.clone())
        .prompt()
        .unwrap();
    let sk = match options
        .iter()
        .position(|e| *e == picked)
        .expect("unexpected option")
    {
        0 => keypair_gen().0,
        1 => keypair_from_hex(&Text::new("Paste hex here:").prompt().unwrap())?.0,
        2 => keypair_from_bip39(&Text::new("Mnemonic phrase:").prompt().unwrap())?.0,
        _ => panic!("unexpected option"),
    };

    let name = Text::new("Wallet name:").prompt().unwrap();
    let password = Password::new("Password:").prompt().unwrap();

    write_to_keystore(sk, args.keystore_dir, name, password)
}

async fn provide(args: ProvideArgs) -> anyhow::Result<()> {
    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = read_from_keystore(keystore, password)?;

    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await?;

    let target_address = Address::from_str(&args.target_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let (alice, mut to_alice) = Maker::new(eth_provider.clone(), wallet, target_address, args.time_lock_param).unwrap();

    tokio::spawn(async {
        alice.run().await;
    });

    server::serve(to_alice).await;

    Ok(())
}

async fn swap(args: SwapArgs) -> anyhow::Result<()> {
    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = read_from_keystore(keystore, password)?;

    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await?;

    let client = client::Client::new(args.maker_address)?;

    let mut bob = Taker::new(eth_provider.clone(), wallet, args.amount, args.time_lock_param);
    let setup_msg = bob.setup1()?;

    let alice_setup_msg = client.setup(setup_msg).await?;

    println!("setup complete: key share generated, time-locked commitments exchanged.");

    let lock_msg1 = bob.setup2(alice_setup_msg).await?;

    let alice_lock_msg = client.lock(args.target_address.clone(), args.amount, lock_msg1).await?;

    let lock_msg2 = bob.lock(alice_lock_msg)?;

    println!("lock complete: pre-signatures generated.");

    let alice_swap_msg = client.swap(lock_msg2).await?;
    let _ = bob.complete(alice_swap_msg).await?;

    println!("swap complete!");

    let target_address = Address::from_str(&args.target_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;

    loop {
        let wei = eth_provider.provider.get_balance(target_address, None).await.unwrap();
        let eth = wei.as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
        println!("balance of {} is {} ETH", args.target_address, eth);
        sleep(Duration::from_secs(1));
        if eth == args.amount {
            break
        }
    }

    Ok(())
}
