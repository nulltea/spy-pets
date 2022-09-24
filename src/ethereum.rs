use std::ops::Add;
use anyhow::anyhow;
use async_trait::async_trait;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use ethers::core::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use ethers::utils::{keccak256, parse_ether};
pub use ethers::utils::WEI_IN_ETHER;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use url::Url;
use crate::types::transaction::eip2718::TypedTransaction;
use futures::{pin_mut, StreamExt};
use tokio::pin;


#[derive(Clone)]
pub struct Ethereum {
    pub provider: Provider<Http>,
    chain_id: u64,
}

impl Ethereum {
    pub async fn new(url: impl Into<Url>) -> anyhow::Result<Self> {
        let provider = Provider::new(Http::new(url));
        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|_e| anyhow!("error making request to the specified Ethereum RPC address"))?;

        Ok(Self {
            provider,
            chain_id: chain_id.as_u64(),
        })
    }

    pub fn compose_tx(
        &self,
        from: Address,
        to: Address,
        amount: f64,
    ) -> anyhow::Result<(TypedTransaction, H256)> {
        let mut tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .gas_price(1000000000)// self.provider.get_gas_price().await.unwrap(
            .gas(21000)
            .chain_id(self.chain_id)
            .value(parse_ether(amount).map_err(|e| anyhow!("error parsing ether: {e}"))?).into();

        self.provider.fill_transaction(&mut tx, None);

        let tx_hash = tx.sighash();

        Ok((tx, tx_hash))
    }

    pub async fn send(&self, tx: TypedTransaction, wallet: &LocalWallet) -> anyhow::Result<H256> {
        let signer = wallet.clone().with_chain_id(self.chain_id);
        let client = SignerMiddleware::new(self.provider.clone(), signer);
        let pending = client.send_transaction(tx, None).await?;

        Ok(match pending.await {
            Ok(Some(rec)) => rec.transaction_hash,
            Ok(None) => {
                panic!("expected transaction receipt");
            }
            Err(_e) => {
                panic!("fatal error sending tx");
            }
        })
    }

    pub async fn send_signed(&self, tx: TypedTransaction, sig: &two_party_adaptor::Signature) -> anyhow::Result<H256> {
        let from = tx.from().unwrap().clone();
        let m = tx.sighash();
        let r = U256::from_big_endian(&sig.r.to_bytes());
        let s = U256::from_big_endian(&sig.s.to_bytes());
        let v = {
            let v = to_eip155_v(1, self.chain_id);
            let recid = Signature { r, s, v }.verify(m, from).is_ok() as u8;
            to_eip155_v(recid, self.chain_id)
        };

        let encoded_tx = tx.rlp_signed(&Signature { r, s, v });

        Signature { r, s, v }
            .verify(m, from)
            .map_err(|e| anyhow!("verification error: {e}"))?;

        let pending = self
            .provider
            .send_raw_transaction(encoded_tx)
            .await
            .map_err(|e| anyhow!("error sending raw decrypted transaction: {e}"))?;


        Ok(match pending.await {
            Ok(Some(rec)) => rec.transaction_hash,
            Ok(None) => {
                panic!("expected transaction receipt");
            }
            Err(_e) => {
                panic!("fatal error sending tx");
            }
        })
    }

    pub async fn listen_for_signature(&self, address: Address) -> anyhow::Result<two_party_adaptor::Signature> {
        let mut pending_txns = self.provider.watch_pending_transactions().await.unwrap();
        let pending_txns = pending_txns.filter_map(|tx_hash| async move {
            return match self.provider
                .get_transaction(tx_hash)
                .await
                .map_err(|e| anyhow!("error getting tx: {e}"))
                .map(|v| {
                    v.map(|tx| {
                        let mut r = [0; 32];
                        let mut s = [0; 32];

                        tx.r.to_big_endian(&mut r);
                        tx.s.to_big_endian(&mut s);

                        (tx.from, two_party_adaptor::Signature {
                            r: two_party_adaptor::BigInt::from_bytes(&r),
                            s: two_party_adaptor::BigInt::from_bytes(&s),
                        })
                    })
                })
            {
                Ok(Some((from, sig))) =>
                    if from == address {
                        Some(Ok(sig))
                    } else {
                        None
                    }
                Err(e) => {
                    return Some(Err(e))
                },
                _ => None
            }
        }).fuse();
        pin!(pending_txns);
        pending_txns.select_next_some().await
    }

    pub fn address_from_pk(&self, pk: &Point<Secp256k1>) -> Address {
        let public_key = PublicKey::from_sec1_bytes(&pk.to_bytes(false)).unwrap();
        let public_key = public_key.to_encoded_point(false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);
        Address::from_slice(&hash[12..])
    }
}
