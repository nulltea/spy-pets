use anyhow::anyhow;
use ethers::prelude::coins_bip39::English;
use ethers::prelude::MnemonicBuilder;
use std::fs;
use std::path::Path;
use std::str::FromStr;
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
