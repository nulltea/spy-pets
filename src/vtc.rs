use std::future::Future;
use std::time::Duration;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use htlp::{BigUint, lhp, ToBigUint};
use htlp::structures::{Params, Puzzle};
use serde::{Serialize, Deserialize};
use tlock::client::{ChainInfo, Network};
use tlock::ibe::Ciphertext;
use tokio::task::JoinError;

pub trait TimeLock {
    fn lock(&self, w: &Scalar<Secp256k1>, d: &Duration) -> VTC;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLockParams {
    network_host: String,
    chain_hash: String,
    round_number: u64,
}

#[derive(Clone)]
pub struct HTLP {
    security_bits: u64,
    time_param: BigUint
}

impl HTLP {
    pub fn new(security_bits: usize, time_param: u64) -> Self {
        Self {
            security_bits: security_bits as u64,
            time_param: time_param.to_biguint().unwrap()
        }
    }
}

impl TimeLock for HTLP {
    fn lock(&self, w: &Scalar<Secp256k1>, _d: &Duration) -> VTC {
        let pp = lhp::setup::setup(
            self.security_bits,
            self.time_param.to_biguint().unwrap(),
        );
        let c = lhp::generate::gen(
            &pp,
            BigUint::from_bytes_be(&*w.to_bigint().to_bytes()),
        );

        VTC::HTLP(pp, c)
    }
}

#[derive(Clone)]
pub struct TLock {
    network: Network,
    host_url: String,
    info: ChainInfo,
}

impl TLock {
    pub async fn new<S: AsRef<str> + Copy>(host: S, chain_hash: impl AsRef<str>) -> anyhow::Result<Self> {
        let network = Network::new(host, chain_hash)?;
        let info = network.info().await?;

        Ok(Self {
            network,
            host_url: host.as_ref().to_string(),
            info
        })
    }
}

impl TimeLock for TLock {
    fn lock(&self, w: &Scalar<Secp256k1>, d: &Duration) -> VTC {
        let round_number = tlock::time::round_after(&self.info, d.clone());
        let message: [u8; 32] = w.to_bytes().to_vec().try_into().unwrap();
        let c = tlock::time_lock(self.info.public_key, round_number, message);
        VTC::TLock(TLockParams{
            network_host: self.host_url.clone(),
            chain_hash: self.info.hash.clone(),
            round_number
        }, c)
    }
}

#[derive(Clone)]
pub struct VariableVTC {
    htlp: Option<HTLP>,
    tlock: Option<TLock>,
}

impl VariableVTC {
    pub fn new_htlp(security_bits: usize, time_param: u64) -> Self {
        Self {
            htlp: Some(HTLP::new(security_bits, time_param)),
            tlock: None
        }
    }

    pub async fn new_tlock<S: AsRef<str> + Copy>(host: S, chain_hash: impl AsRef<str>) -> anyhow::Result<Self> {
        Ok(Self {
            htlp: None,
            tlock: Some(TLock::new(host, chain_hash).await?)
        })
    }
}

impl TimeLock for VariableVTC {
    fn lock(&self, w: &Scalar<Secp256k1>, d: &Duration) -> VTC {
        if let Some(htlp) = self.htlp.as_ref() {
            return htlp.lock(w, d)
        }

        self.tlock.as_ref().unwrap().lock(w, d)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VTC {
    HTLP(Params, Puzzle),
    TLock(TLockParams, Ciphertext)
}


impl VTC {
    pub fn verify(&self, _local_share: &Scalar<Secp256k1>, _pub_key: &Point<Secp256k1>) -> bool {
        match self {
            VTC::HTLP(_, _) => true,
            VTC::TLock(_, _) => true
        }
    }

    pub fn unlock(self) -> impl Future<Output=Result<Scalar<Secp256k1>, JoinError>> {
        match self {
            VTC::HTLP(pp, c) => {
                tokio::task::spawn_blocking(move || {
                    Scalar::from_bigint(&BigInt::from_bytes(&lhp::solve::solve(&pp, &c).to_bytes_be()))
                })
            },
            VTC::TLock(pp, c) => {
                tokio::task::spawn(async move {
                    let network = Network::new(pp.network_host, pp.chain_hash).unwrap();
                    let info = network.info().await.unwrap();
                    let dur = tlock::time::dur_before(&info, pp.round_number);
                    tokio::time::sleep(dur).await;
                    let beacon = network.get(pp.round_number).await.expect("drand beacon is expected");
                    Scalar::from_bytes(&tlock::time_unlock(beacon, &c)).unwrap()
                })
            }
        }
    }
}
