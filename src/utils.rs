use anyhow::anyhow;
use ethers::prelude::coins_bip39::English;
use ethers::prelude::*;
use std::fs;
use std::path::Path;

use crate::k256::ecdsa::SigningKey;
use crate::types::transaction::eip2718::TypedTransaction;
use crate::types::transaction::eip712::Eip712;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

pub fn keypair_gen() -> (Scalar<Secp256k1>, Point<Secp256k1>) {
    let sk = Scalar::random();
    let pk = Point::generator() * &sk;
    (sk, pk)
}

pub fn keypair_from_hex(s: &str) -> anyhow::Result<(Scalar<Secp256k1>, Point<Secp256k1>)> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("error parsing hex: {e}"))?;
    let sk = Scalar::from_bytes(&*bytes).map_err(|e| anyhow!("error parsing scalar: {e}"))?;
    let pk = Point::generator() * &sk;
    Ok((sk, pk))
}

pub fn keypair_from_bip39(phrase: &str) -> anyhow::Result<(Scalar<Secp256k1>, Point<Secp256k1>)> {
    let sk_bytes = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .build()
        .map_err(|e| anyhow!("error parsing mnemonic: {e}"))?
        .signer()
        .to_bytes();
    let sk = Scalar::from_bytes(sk_bytes.as_slice()).unwrap();
    let pk = Point::generator() * &sk;
    Ok((sk, pk))
}

pub fn write_to_keystore<D: AsRef<Path>, S: AsRef<str>, P: AsRef<[u8]>>(
    sk: Scalar<Secp256k1>,
    dir: D,
    name: S,
    password: P,
) -> anyhow::Result<()> {
    let _ = fs::create_dir_all(&dir);
    eth_keystore::encrypt_key(
        dir,
        &mut rand::thread_rng(),
        &*sk.to_bytes(),
        password,
        Some(name.as_ref()),
    )
    .map_err(|e| anyhow!("error encrypting key: {e}"))
    .map(|_| ())
}

pub fn read_from_keystore<P: AsRef<Path>, S: AsRef<[u8]>>(
    path: P,
    password: S,
) -> anyhow::Result<LocalWallet> {
    let sk_bytes = eth_keystore::decrypt_key(path, password);
    let sk = SigningKey::from_bytes(sk_bytes?.as_slice())
        .map_err(|e| anyhow!("error parsing key: {e}"))?;
    Ok(LocalWallet::from(sk))
}

#[derive(Debug)]
pub struct KeylessWallet {
    address: Address,
    chain_id: u64,
}

impl KeylessWallet {
    pub fn new(address: Address, chain_id: u64) -> Self {
        Self { address, chain_id }
    }
}

#[async_trait]
impl Signer for KeylessWallet {
    type Error = WalletError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        _message: S,
    ) -> Result<Signature, Self::Error> {
        todo!()
    }

    async fn sign_transaction(&self, _message: &TypedTransaction) -> Result<Signature, Self::Error> {
        todo!()
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        _payload: &T,
    ) -> Result<Signature, Self::Error> {
        todo!()
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }
}
