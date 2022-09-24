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

async fn setup(args: SetupArgs) {

}

async fn provide(args: ProvideArgs) {
    let amount = 1.0;
    let rpc_url = Url::parse("http://127.0.0.1:8545").unwrap();
    let eth_provider = Ethereum::new(rpc_url).await.unwrap();
    let alice_wallet = LocalWallet::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();

    let alice_addr2 = Address::from_str("1B663f7F4eE9fe8D9c491bb3679f1ad7560cfA99").unwrap();
    let (alice, mut to_alice) = Maker::new(eth_provider.clone(), alice_wallet, alice_addr2).unwrap();

    tokio::spawn(async {
        alice.run().await;
    });

    server::serve(to_alice).await;
}

async fn swap(args: SwapArgs) {
    // let amount = 1.0;
    // let rpc_url = Url::parse("http://127.0.0.1:8545").unwrap();
    // let eth_provider = Ethereum::new(rpc_url).await.unwrap();
    // let alice_wallet = LocalWallet::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    //
    // let alice_addr2 = Address::from_str("1B663f7F4eE9fe8D9c491bb3679f1ad7560cfA99").unwrap();
    // let (alice, mut to_alice) = Maker::new(eth_provider.clone(), alice_wallet, alice_addr2).unwrap();
    //
    // tokio::spawn(async {
    //     alice.run().await;
    // });
    //
    // let bob_wallet = LocalWallet::from_str("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d").unwrap();
    // let bob_addr2 = Address::from_str("DB2441c05Ec776BE89C6BC9bE98CB74e671E5aF0").unwrap();
    // let mut bob = Taker::new(eth_provider.clone(), bob_wallet, bob_addr2, amount);
    // let bob_setup_msg1 = bob.setup1().unwrap();
    //
    // let (resp_tx, resp_rx) = oneshot::channel();
    // let _ = to_alice.send(maker::MakerMsg::Setup {
    //     msg: bob_setup_msg1,
    //     resp_tx
    // }).await;
    // let alice_setup_msg = resp_rx.await.unwrap().unwrap();
    //
    // let bob_setup_msg1 = bob.setup2(alice_setup_msg).await.unwrap();
    //
    // let (resp_tx, resp_rx) = oneshot::channel();
    // let _ = to_alice.send(maker::MakerMsg::Lock1 {
    //     amount,
    //     msg: bob_setup_msg1,
    //     resp_tx
    // }).await;
    // let alice_lock_msg1 = resp_rx.await.unwrap().unwrap();
    //
    // let bob_lock_msg = bob.lock(alice_lock_msg1).unwrap();
    //
    // let (resp_tx, resp_rx) = oneshot::channel();
    // let _ = to_alice.send(maker::MakerMsg::Lock2 {
    //     msg: bob_lock_msg,
    //     resp_tx
    // }).await;
    // let alice_lock_msg2 = resp_rx.await.unwrap().unwrap();
    // let _ = bob.complete(alice_lock_msg2).await.unwrap();
    //
    // loop {
    //     let x = eth_provider.provider.get_balance(bob_addr2, None).await.unwrap();
    //     let b = x / WEI_IN_ETHER;
    //     println!("balance of bob's {bob_addr2} is {}", b.as_u64());
    //     let x = eth_provider.provider.get_balance(alice_addr2, None).await.unwrap();
    //     let b = x / WEI_IN_ETHER;
    //     println!("balance of alice's {bob_addr2} is {}", b.as_u64());
    //     sleep(Duration::from_secs(2))
    // }
}
