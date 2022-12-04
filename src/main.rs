#![feature(async_closure)]
#[macro_use]
extern crate rocket;

use std::future::Future;
use std::path::Path;

use anyhow::anyhow;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use cli_batteries::version;
use ethers::abi::AbiEncode;

use ethers::prelude::*;
use ethers::prelude::builders::ContractCall;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::{format_units, parse_ether};

use inquire::{Password, Select, Text};
use serde::Deserialize;
use serde_json::json;
use tracing::{info_span, Instrument};
use uniswap_rs::bindings::ierc20::ierc20;
use uniswap_rs::Dex;
use url::Url;

use crate::args::Options;
use crate::args::*;
use crate::ethereum::{Ethereum, WEI_IN_ETHER};
use crate::maker::Maker;
use crate::taker::{CovertTransaction, Taker};
use crate::utils::{KeylessWallet, keypair_from_bip39, keypair_from_hex, keypair_gen, read_from_keystore, write_to_keystore};

mod args;
mod client;
mod ethereum;
mod maker;
mod server;
mod taker;
mod utils;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(opts: Options) -> eyre::Result<()> {
    if let Some(command) = opts.command {
        match command {
            Command::Setup(args) => setup(args).await.map_err(|e| eyre::anyhow!(e))?,
            Command::Provide(args) => provide(args).await.map_err(|e| eyre::anyhow!(e))?,
            Command::Transfer(args) => transfer(args)
                .instrument(info_span!("transfer"))
                .await
                .map_err(|e| eyre::anyhow!(e))?,
            Command::Uniswap(args) => uniswap_swap(args)
                .instrument(info_span!("uniswap::swap"))
                .await
                .map_err(|e| eyre::anyhow!(e))?,
            Command::BuyNft(args) => buy_nft(args)
                .instrument(info_span!("opensea::buy"))
                .await
                .map_err(|e| eyre::anyhow!(e))?,
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
    info!("Bob's address: {}", wallet.address());

    let eth_provider = Ethereum::new(&args.network).await?;

    let target_address = Address::from_str(&args.secondary_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let (alice, to_alice) = Maker::new(
        eth_provider.clone(),
        wallet,
        target_address,
        args.time_lock_param,
    )
    .unwrap();

    tokio::spawn(async {
        alice.run().await;
    });

    server::serve(to_alice, args.server_address).await;

    Ok(())
}

async fn transfer(args: TransferArgs) -> anyhow::Result<()> {
    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = read_from_keystore(keystore, password)?;
    info!("Alice's address: {}", wallet.address());

    let eth_provider = Ethereum::new(&args.network).await?;

    let client = client::Client::new(args.relay_address)?;

    let target_address = Address::from_str(&args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let mut alice = Taker::new(
        eth_provider.clone(),
        wallet,
        args.amount,
        args.time_lock_param,
    );
    let setup_msg = info_span!("taker::setup1").in_scope(|| alice.setup1())?;

    let bob_setup_msg = client.setup(args.amount, setup_msg).await?;

    info!("setup complete: key share generated, time-locked commitments exchanged.");

    let lock_msg1 = alice
        .setup2(bob_setup_msg)
        .instrument(info_span!("taker::setup2"))
        .await?;

    let bob_lock_msg = client.lock(lock_msg1).await?;

    let lock_msg2 = alice
        .lock(bob_lock_msg, CovertTransaction::Swap(args.amount, target_address))
        .instrument(info_span!("taker::lock"))
        .await?;

    info!("lock complete: pre-signatures generated.");

    let bob_swap_msg = client.swap(lock_msg2).await?;
    let _ = alice
        .complete(bob_swap_msg)
        .instrument(info_span!("taker::swap"))
        .await?;

    info!("transfer completed!");

    let target_address = Address::from_str(&args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;

    loop {
        let wei = eth_provider
            .provider
            .get_balance(target_address, None)
            .await
            .unwrap();
        let eth = wei.as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
        info!("balance of {} is {} ETH", args.target_address, eth);
        sleep(Duration::from_secs(1));
        if eth == args.amount {
            break;
        }
    }

    Ok(())
}

async fn covert_contract_call<Fut>(
    args: TransferArgs,
    compose_tx: impl FnOnce(Address, Address) -> Fut,
) -> anyhow::Result<()> where Fut: Future<Output=Vec<TypedTransaction>> {
    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = read_from_keystore(keystore, password)?;
    info!("Alice's address: {}", wallet.address());

    let eth_provider = Ethereum::new(&args.network).await?;

    let client = client::Client::new(args.relay_address)?;

    let target_address = Address::from_str(&args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;
    let mut alice = Taker::new(
        eth_provider.clone(),
        wallet.clone(),
        args.amount,
        args.time_lock_param,
    );
    let setup_msg = info_span!("taker::setup1").in_scope(|| alice.setup1())?;

    let bob_setup_msg = client.setup(args.amount, setup_msg).await?;

    info!("setup complete: key share generated, time-locked commitments exchanged.");

    let lock_msg1 = alice
        .setup2(bob_setup_msg)
        .instrument(info_span!("taker::setup2"))
        .await?;

    info!("CoinSwap Address 2: {}", alice.s2_address());

    let bob_lock_msg = client.lock(lock_msg1).await?;

    let tx = compose_tx(alice.s2_address(), target_address).await;

    let lock_msg2 = alice
        .lock(bob_lock_msg, CovertTransaction::CustomTx(tx))
        .instrument(info_span!("taker::lock"))
        .await?;

    info!("lock complete: pre-signatures generated.");

    let bob_swap_msg = client.swap(lock_msg2).await?;
    let _ = alice
        .complete(bob_swap_msg)
        .instrument(info_span!("taker::swap"))
        .await.unwrap();

    Ok(())
}

abigen!(
    IErc20,
    r#"[
            function balanceOf(address account) external view returns (uint256)
    ]"#,
);

async fn uniswap_swap(args: UniswapArgs) -> anyhow::Result<()> {
    let chain = Ethereum::new(&args.base_args.network).await?;
    let usdc = uniswap_rs::contracts::address(&args.target_erc20, Chain::Goerli);

    let block = chain.provider.get_block(BlockNumber::Latest).await?.unwrap();

    // get the max basefee 5 blocks in the future, just in case
    let base_fee = block.base_fee_per_gas.expect("No basefee found");
    info!("Current base fee {:?}", base_fee);
    let mut max_base_fee = base_fee;
    for _ in 0..5 {
        max_base_fee *= 1125;
        max_base_fee /= 1000;
    }
    info!("Max base fee {:?}", max_base_fee);

    let erc20 = IErc20::new(usdc, chain.provider.clone());

    let eth_provider = chain.clone();

    covert_contract_call(args.base_args.clone(), async move |address_from, address_to| {
        let shared_wallet = KeylessWallet::new(address_from, chain.chain_id());
        let mut dex = {
            let client = Arc::new({
                SignerMiddleware::new(eth_provider.provider.clone(), shared_wallet)
            });

            Dex::new_with_chain(client, Chain::Goerli, uniswap_rs::ProtocolType::UniswapV2)
        };

        // get contract addresses from address book
        // swap amount
        let amount = uniswap_rs::Amount::ExactIn(parse_ether(&args.base_args.amount).unwrap());

        // construct swap path
        // specify native ETH by using NATIVE_ADDRESS or Address::repeat_byte(0xee)
        let eth = uniswap_rs::constants::NATIVE_ADDRESS;
        let path = [eth, usdc];

        // create the swap transaction
        let mut call = dex.swap(amount, 0.5, &path, Some(address_to), None).await.unwrap();
        let mut tx = match call.tx {
            TypedTransaction::Eip1559(inner) => inner,
            _ => panic!("Did not expect non-1559 tx"),
        };

        // initialize the max base fee value, without any priority fee
        tx.max_fee_per_gas = Some(max_base_fee);

        vec![TypedTransaction::Eip1559(tx)]
    }).await?;

    info!("swap completed!");

    let target_address = Address::from_str(&args.base_args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;

    loop {
        let balance = erc20.balance_of(target_address).call().await.unwrap();
        let tokens: f64 = format_units(balance, 0)?.parse()?;
        info!("balance of {} is {} {}", args.base_args.target_address, tokens, args.target_erc20);
        sleep(Duration::from_secs(1));
        if tokens != 0.0 {
            break;
        }
    }

    Ok(())
}

ethers::contract::abigen!(
    IErc721,
    r#"[
        function ownerOf(uint256) view returns (address)
        function safeTransferFrom(address,address,uint256) external;
    ]"#
);

ethers::contract::abigen!(
    IErc1155,
    r#"[
        function balanceOf(address,uint256) view returns (uint256)
        function safeTransferFrom(address,address,uint256,uint256,bytes memory) external;
    ]"#
);

async fn buy_nft(args: BuyNFTArgs) -> anyhow::Result<()> {
    let chain = Ethereum::new(&args.base_args.network).await?;

    let block = chain.provider.get_block(BlockNumber::Latest).await?.unwrap();
    let timestamp = block.timestamp.as_u64();

    // get the max basefee 5 blocks in the future, just in case
    let base_fee = block.base_fee_per_gas.expect("No base-fee found");
    info!("Current base fee {:?}", base_fee);
    let mut max_base_fee = base_fee;
    for _ in 0..5 {
        max_base_fee *= 1125;
        max_base_fee /= 1000;
    }
    info!("Max base fee {:?}", max_base_fee);

    let target_address = Address::from_str(&args.base_args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;

    let marketplace_api: surf::Client = {
        let url = Url::parse("https://api.gaming.chainsafe.io").unwrap();
        surf::Config::new().set_base_url(url).set_timeout(None).try_into().unwrap()
    };

    let mut resp = marketplace_api
        .post("/evm/getListedNfts")
        .body_json(&json!({
                "chain": "ethereum",
                "network": "goerli",
            }))
        .unwrap()
        .await
        .map_err(|e| anyhow!("error requesting setup: {e}"))?;

    if resp.status() != 200 {
        return Err(anyhow!("{}", resp.body_string().await.unwrap()));
    }

    #[derive(Deserialize)]
    struct Nft {
        itemId: String,
        nftContract: String,
        tokenId: String,
        price: String,
        tokenType: String
    }

    #[derive(Deserialize)]
    struct NftResponse {
        response: Vec<Nft>
    }

    let nfts = resp.body_json::<NftResponse>()
        .await
        .unwrap();

    let nft = {
        let nft_contract = hex::encode_upper(args.nft_contract.to_fixed_bytes());
        let token_id = hex::encode_upper(args.token_id.encode());
        match nfts.response.into_iter().find(|e| e.nftContract.trim_start_matches("0x").to_uppercase() == nft_contract && e.tokenId.trim_start_matches("0x").to_uppercase() == token_id) {
            None => Err(anyhow!("nft not found in marketplace")),
            Some(mut nft) => {
                let item_id: u8 = nft.itemId.parse().unwrap();
                let price: u64 = nft.price.parse().unwrap();
                Ok(Nft{
                    itemId: format!("0x{}", hex::encode(item_id.to_le_bytes())),
                    price: format!("0x{}", hex::encode(price.to_be_bytes())),
                    ..nft
                })
            }
        }
    }?;

    let provider = chain.provider.clone();
    let is_erc1155 = nft.tokenType == "1155";

    #[derive(Deserialize)]
    struct Tx {
        to: NameOrAddress,
        value: U256,
        data: Bytes,
    }

    #[derive(Deserialize)]
    struct PreparedTx {
        tx: Tx
    }

    #[derive(Deserialize)]
    struct TxResponse {
        response: PreparedTx
    }

    covert_contract_call(args.base_args.clone(), async move |address_from, address_to| {
        let shared_wallet = KeylessWallet::new(address_from, chain.chain_id());

        let mut resp = marketplace_api
            .post("/evm/createPurchaseNftTransaction")
            .body_json(&json!({
                "account": "0x1B663f7F4eE9fe8D9c491bb3679f1ad7560cfA99",//format!("0x{}", hex::encode(shared_wallet.address().to_fixed_bytes())),
                "chain": "ethereum",
                "itemId": nft.itemId,
                "network": "goerli",
                "price": nft.price,
                "tokenType": nft.tokenType,
            }))
            .unwrap()
            .await
            .map_err(|e| anyhow!("error requesting setup: {e}")).unwrap();

        if resp.status() != 200 {
            panic!("{}", resp.body_string().await.unwrap());
        }

        let prepared_tx = resp.body_json::<TxResponse>()
            .await
            .unwrap().response.tx;

        let purchase_tx = TypedTransaction::Eip1559(Eip1559TransactionRequest {
            from: Some(shared_wallet.address()),
            to: Some(prepared_tx.to),
            value: Some(prepared_tx.value),
            data: Some(prepared_tx.data),
            max_priority_fee_per_gas: Some(max_base_fee),
            max_fee_per_gas: Some(max_base_fee),
            ..Default::default()
        });

        let transfer_tx = {
            let call = if is_erc1155 {
                IErc1155::new(args.nft_contract, chain.provider.clone()).safe_transfer_from(
                    shared_wallet.address(), target_address, args.token_id, U256::one(), Bytes::default()
                )
            } else {
                IErc721::new(args.nft_contract, chain.provider.clone()).safe_transfer_from(
                    shared_wallet.address(), target_address, args.token_id
                )
            };

            let mut tx = match call.tx {
                TypedTransaction::Eip1559(inner) => inner,
                _ => panic!("Did not expect non-1559 tx"),
            };

            // initialize the max base fee value, without any priority fee
            tx.max_fee_per_gas = Some(max_base_fee);
            // tx.from = Some(shared_wallet.address());
            tx.nonce = Some(U256::from(1));

            TypedTransaction::Eip1559(tx)
        };

        vec![purchase_tx, transfer_tx]
    }).await?;

    info!("purchase completed!");

    info!("Ownership after:");
    let target_address = Address::from_str(&args.base_args.target_address)
        .map_err(|e| anyhow!("error parsing target address: {e}"))?;
    if is_erc1155 {
        let balance = IErc1155::new(args.nft_contract, provider.clone()).balance_of(target_address, args.token_id).call().await?;
        info!("{:?} owns {:?} ERC1155 NFTs with token id {:?}", target_address, balance, args.token_id);
    } else {
        let owner = IErc721::new(args.nft_contract, provider.clone()).owner_of(args.token_id).call().await?;
        info!("Owner of ERC721 NFTs with token id {:?}: {:?}", args.token_id, owner);
    }

    Ok(())
}
