use anyhow::anyhow;

use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;
use crate::WEI_IN_ETHER;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use htlp::{lhp, ToBigUint};
use serde::{Deserialize, Serialize};
use two_party_adaptor::party_one;
use two_party_adaptor::party_two::{keygen, sign, EcKeyPair};

pub const SALT_STRING: &[u8] = &[75, 90, 101, 110];

#[derive(Clone)]
pub struct Taker {
    amount: f64,
    target_address: Address,
    refund_time_param: u64,

    s1: Party2SharedAccountState,
    s2: Party2SharedAccountState,

    sign_p1_pub_share: Option<Point<Secp256k1>>,
    sign_local: Option<sign::PreSignRound1Local>,
    sign_share: Option<EcKeyPair>,
    adaptor_wit: Scalar<Secp256k1>,

    tx: Option<TypedTransaction>,

    chain: Ethereum,
    wallet: LocalWallet,
}

#[derive(Clone, Default)]
struct Party2SharedAccountState {
    key_share: Option<EcKeyPair>,
    key_p1_msg1: Option<party_one::keygen::KeyGenMsg2>,
    shared_pk: Option<Point<Secp256k1>>,
}

pub type SetupMsg = (keygen::KeyGenMsg1, keygen::KeyGenMsg1);

pub type LockMsg1 = sign::PreSignMsg1;

#[derive(Debug, Serialize, Deserialize)]
pub struct LockMsg2 {
    pub account1: sign::PreSignMsg2,
    pub account2: sign::PreSignMsg2,
    pub vtc_params: htlp::structures::Params,
    pub refund_vtc: htlp::structures::Puzzle,
}

impl Taker {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        target_address: Address,
        amount: f64,
        refund_time_param: u64,
    ) -> Self {
        Self {
            amount,
            target_address,
            refund_time_param,
            s1: Default::default(),
            s2: Default::default(),
            sign_p1_pub_share: Default::default(),
            sign_local: Default::default(),
            sign_share: Default::default(),
            adaptor_wit: Scalar::<Secp256k1>::random(),
            tx: Default::default(),
            chain: chain_provider,
            wallet,
        }
    }

    pub fn setup1(&mut self) -> anyhow::Result<SetupMsg> {
        let msg1 = {
            let (res, key_share) = keygen::first_message();
            let _ = self.s1.key_share.insert(key_share);
            res
        };

        let msg2 = {
            let (res, key_share) = keygen::first_message();
            let _ = self.s2.key_share.insert(key_share);
            res
        };

        return Ok((msg1, msg2));
    }

    pub async fn setup2(&mut self, msg: crate::maker::SetupMsg) -> anyhow::Result<LockMsg1> {
        let _ = self.s1.key_p1_msg1.insert(msg.account1.1.clone());
        let _ = self.s2.key_p1_msg1.insert(msg.account2.1.clone());

        {
            keygen::second_message(&msg.account1.0, &msg.account1.1, SALT_STRING)
                .map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.s1.key_share.as_ref().unwrap(),
                &msg.account1.0.public_share,
            );
            let _ = self.s1.shared_pk.insert(shared_pk);
        };

        {
            keygen::second_message(&msg.account2.0, &msg.account2.1, SALT_STRING)
                .map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.s2.key_share.as_ref().unwrap(),
                &msg.account2.0.public_share,
            );
            let _ = self.s2.shared_pk.insert(shared_pk);
        };

        let (res, local) = sign::first_message(&self.adaptor_wit);
        let _ = self.sign_local.insert(local); // todo: ensure that it's fine to reuse k2 for multiple txns

        return Ok(res);
    }

    pub async fn lock(&mut self, msg: crate::maker::LockMsg) -> anyhow::Result<LockMsg2> {
        let _ = self
            .sign_p1_pub_share
            .insert(msg.commitments.public_share.clone());

        // todo: verify VTC

        {
            let me = self.clone();
            let pp = msg.vtc_params.clone();
            let vtc = msg.refund_vtc.clone();
            tokio::task::spawn_blocking(move || {
                let dlog = lhp::solve::solve(&pp, &vtc);
                tokio::task::spawn(async move {
                    let addr = me.chain.address_from_pk(me.s1.shared_pk.as_ref().unwrap());
                    let balance = me
                        .chain
                        .provider
                        .get_balance(addr, None)
                        .await
                        .unwrap()
                        .as_u64() as f64
                        / WEI_IN_ETHER.as_u64() as f64;
                    if balance > me.amount {
                        let x_p1 = Scalar::from_bigint(&BigInt::from_bytes(&dlog.to_bytes_be()));
                        let full_sk = &x_p1 * &me.s1.key_share.as_ref().unwrap().secret_share;
                        let signer = LocalWallet::from(
                            SigningKey::from_bytes(&*full_sk.to_bytes()).unwrap(),
                        );
                        let (tx, _) = me
                            .chain
                            .compose_tx(addr, me.wallet.address(), me.amount)
                            .unwrap();
                        me.chain.send(tx, &signer).await.unwrap();
                        warn!(
                            "swap failed, funds were refunded to {}",
                            me.wallet.address()
                        );
                    } else {
                        info!("timeout passed, all good.");
                    }
                });
            });
        }

        let local_addr = self.wallet.address();
        let s1 = self
            .chain
            .address_from_pk(self.s1.shared_pk.as_ref().unwrap());
        let (tx, _) = self
            .chain
            .compose_tx_with_fee(local_addr, s1, self.amount)
            .expect("tx to compose");
        let _ = self.chain.send(tx, &self.wallet).await?;

        let s2 = self
            .chain
            .address_from_pk(self.s2.shared_pk.as_ref().unwrap());
        let (tx, tx_hash) = self
            .chain
            .compose_tx(s2, self.target_address, self.amount)
            .expect("tx to compose");
        let _ = self.tx.insert(tx);

        let pre_sig1 = {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } =
                self.s1.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &msg.commitments,
                ek,
                c_key,
                &self.s1.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &msg.commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &msg.tx_hash,
            )
            .map_err(|e| anyhow!("error in signing round 2: {e}"))
        }?;

        let pre_sig2 = {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } =
                self.s2.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &msg.commitments,
                ek,
                c_key,
                &self.s2.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &msg.commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &BigInt::from_bytes(&tx_hash.to_fixed_bytes()[..]),
            )
            .map_err(|e| anyhow!("error in signing round 2: {e}"))
        }?;

        let vtc_params = lhp::setup::setup(
            two_party_adaptor::SECURITY_BITS as u64,
            self.refund_time_param.to_biguint().unwrap(),
        );
        let refund_witness = self.s1.key_share.as_ref().unwrap().secret_share.to_bigint();
        let refund_vtc = lhp::generate::gen(
            &vtc_params,
            htlp::BigUint::from_bytes_be(&*refund_witness.to_bytes()),
        );

        Ok(LockMsg2 {
            account1: pre_sig1,
            account2: pre_sig2,
            vtc_params,
            refund_vtc,
        })
    }

    pub async fn complete(&mut self, swap_adaptor: crate::maker::SwapMsg) -> anyhow::Result<H256> {
        let sig = sign::decrypt_signature(
            &swap_adaptor,
            &self.adaptor_wit,
            self.sign_p1_pub_share.as_ref().unwrap(),
            &self.sign_local.as_ref().unwrap().k3_pair,
        );

        self.chain.send_signed(self.tx.take().unwrap(), &sig).await
    }
}
