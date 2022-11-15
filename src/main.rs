#[macro_use]
extern crate rocket;

use std::path::Path;

use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use anyhow::anyhow;

use cli_batteries::version;

use ethers::prelude::*;



use inquire::{Password, Select, Text};
use tracing::{info_span, Instrument};

use crate::args::Options;
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

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(opts: Options) -> eyre::Result<()> {
    if let Some(command) = opts.command {
        match command {
            Command::Setup(args) => setup(args).await.map_err(|e| eyre::anyhow!(e))?,
            Command::Provide(args) => provide(args).await.map_err(|e| eyre::anyhow!(e))?,
            Command::Swap(args) => swap(args).instrument(info_span!("swap")).await.map_err(|e| eyre::anyhow!(e))?,
        }
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

    let eth_provider = Ethereum::new(&args.network).await?;

    let target_address = Address::from_str(&args.secondary_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let (alice, to_alice) = Maker::new(eth_provider.clone(), wallet, target_address, args.time_lock_param).unwrap();

    tokio::spawn(async {
        alice.run().await;
    });

    server::serve(to_alice, args.server_address).await;

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

    let eth_provider = Ethereum::new(&args.network).await?;

    let client = client::Client::new(args.relay_address)?;

    let mut bob = Taker::new(eth_provider.clone(), wallet, args.amount, args.time_lock_param);
    let setup_msg = info_span!("taker::setup1").in_scope(|| bob.setup1())?;

    let alice_setup_msg = client.setup(setup_msg).await?;

    info!("setup complete: key share generated, time-locked commitments exchanged.");

    let lock_msg1 = bob.setup2(alice_setup_msg).instrument(info_span!("taker::setup2")).await?;

    let alice_lock_msg = client.lock(args.target_address.clone(), args.amount, lock_msg1).await?;

    let lock_msg2 = info_span!("taker::lock").in_scope(|| bob.lock(alice_lock_msg))?;

    info!("lock complete: pre-signatures generated.");

    let alice_swap_msg = client.swap(lock_msg2).await?;
    let _ = bob.complete(alice_swap_msg).instrument(info_span!("taker::swap")).await?;

    info!("swap complete!");

    let target_address = Address::from_str(&args.target_address).map_err(|e| anyhow!("error parsing target address: {e}"))?;

    loop {
        let wei = eth_provider.provider.get_balance(target_address, None).await.unwrap();
        let eth = wei.as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
        info!("balance of {} is {} ETH", args.target_address, eth);
        sleep(Duration::from_secs(1));
        if eth == args.amount {
            break
        }
    }

    Ok(())
}
