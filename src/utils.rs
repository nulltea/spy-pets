use anyhow::anyhow;
use ethers::prelude::coins_bip39::English;
use ethers::prelude::*;
use std::fs;
use std::path::Path;

use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use crate::k256::ecdsa::SigningKey;

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
    let sk = SigningKey::from_bytes(sk_bytes?.as_slice()).map_err(|e| anyhow!("error parsing key: {e}"))?;
    Ok(LocalWallet::from(sk))
}
