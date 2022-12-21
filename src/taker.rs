use std::time::Duration;
use anyhow::{anyhow, Error};

use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;
use crate::{vtc, WEI_IN_ETHER};
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use htlp::{lhp, ToBigUint};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use two_party_adaptor::party_one;
use two_party_adaptor::party_two::{keygen, sign, EcKeyPair};
use crate::builders::ContractCall;
use crate::vtc::TimeLock;

pub const SALT_STRING: &[u8] = &[75, 90, 101, 110];

#[derive(Clone)]
pub struct Taker<TL: TimeLock + Clone + Send> {
    amount: f64,
    refund_after: Duration,

    s1: Party2SharedAccountState,
    s2: Party2SharedAccountState,

    sign_p1_pub_share: Option<Point<Secp256k1>>,
    sign_local: Option<sign::PreSignRound1Local>,
    sign_share: Option<EcKeyPair>,
    adaptor_wit: Scalar<Secp256k1>,

    txns: Vec<TypedTransaction>,

    chain: Ethereum,
    wallet: LocalWallet,
    time_lock: TL
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
    pub s1: sign::PreSignMsg2,
    pub s2: Vec<sign::PreSignMsg2>,
    pub refund_vtc: vtc::VTC,
    pub tx_gas: U256,
    pub gas_price: U256,
}

pub enum CovertTransaction {
    Swap(f64, Address),
    CustomTx(Vec<TypedTransaction>)
}

impl<TL: TimeLock + Clone + Send> Taker<TL> {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        amount: f64,
        time_lock: TL,
        refund_after: Duration,
    ) -> Self {
        Self {
            amount,
            refund_after,
            s1: Default::default(),
            s2: Default::default(),
            sign_p1_pub_share: None,
            sign_local: None,
            sign_share: None,
            adaptor_wit: Scalar::<Secp256k1>::random(),
            txns: vec![],
            chain: chain_provider,
            wallet,
            time_lock
        }
    }

    pub fn setup1(&mut self) -> anyhow::Result<SetupMsg> {
        /// (a) Alice takes P2’s role in Lindell'17 and computes two `KeyGen::P2::Msg1`,
        /// one for each CoinSwap account (S1, S2):
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
        let _ = self.s1.key_p1_msg1.insert(msg.s1.1.clone());
        let _ = self.s2.key_p1_msg1.insert(msg.s2.1.clone());

        /// (a) Using the both sets of `KeyGen::P1::Msg1` and `KeyGen::P1::Msg2` received from Bob,
        /// Alice computes `KeyGen::P2::Msg2` for S1, S2.
        {
            keygen::second_message(&msg.s1.0, &msg.s1.1, SALT_STRING)
                .map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.s1.key_share.as_ref().unwrap(),
                &msg.s1.0.public_share,
            );
            let _ = self.s1.shared_pk.insert(shared_pk);
        };
        {
            keygen::second_message(&msg.s2.0, &msg.s2.1, SALT_STRING)
                .map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.s2.key_share.as_ref().unwrap(),
                &msg.s2.0.public_share,
            );
            let _ = self.s2.shared_pk.insert(shared_pk);
        };

        /// (b) Alice chooses a random scalar y and computes `Sign::P2::Msg1`.
        let (res, local) = sign::first_message(&self.adaptor_wit);
        let _ = self.sign_local.insert(local); // todo: ensure that it's fine to reuse k2 for multiple txns

        return Ok(res);
    }

    pub async fn lock(&mut self, msg: crate::maker::LockMsg, covert_tx: CovertTransaction, request_delay: Option<Duration>) -> anyhow::Result<LockMsg2> {
        let _ = self
            .sign_p1_pub_share
            .insert(msg.commitments.public_share.clone());

        let crate::maker::LockMsg{
            commitments,
            refund_vtc,
            tx_hash,
            tx_gas,
            gas_price
        } = msg;

        // (a) Alice veriﬁes proof π_a;
        assert!(refund_vtc.verify(
            &self.s1.key_share.as_ref().unwrap().secret_share,
            self.s1.shared_pk.as_ref().unwrap()
        ), "invalid refund VTC");

        // Unlocks VTC and handles refund.
        let me = self.clone();
        tokio::task::spawn(async move {
            // Refund path:
            // (a) After time ta Alice opens timed commitment C_a and acquires Bob’s key share x^S1_p1
            let x_p1 = refund_vtc.unlock().await.unwrap();

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
                // multiples by x^S1_p2 to get valid key x^S1
                let full_sk = &x_p1 * &me.s1.key_share.as_ref().unwrap().secret_share;
                let signer = LocalWallet::from(
                    SigningKey::from_bytes(&*full_sk.to_bytes()).unwrap(),
                );
                // (b) Having x^S1 , Alice can now sign the transaction to transfer α from S1 to other account of her choice.
                let (tx, _) = me
                    .chain
                    .compose_tx(addr, me.wallet.address(), me.amount, Some(gas_price))
                    .unwrap();
                me.chain.send(tx, &signer).await.unwrap();
                warn!("swap failed, funds were refunded to {}", me.wallet.address());
            } else {
                info!("timeout passed, all good.");
            }
        });


        // (b) Alice deposits α coins to S_1 and computes hash h_a of the transaction (...)
        let s2 = self
            .chain
            .address_from_pk(self.s2.shared_pk.as_ref().unwrap());
        let (txns, tx_hashes, gas_total) = match covert_tx {
            CovertTransaction::Swap(amount, address_to) => {
                self
                    .chain
                    .compose_tx(s2, address_to, amount, Some(gas_price))
                    .map(|r| (vec![r.0], vec![r.1], U256::from(21000)))
                    .expect("tx to compose")
            }
            CovertTransaction::CustomTx(mut txs) => {
                let mut gas_total = U256::zero();
                let mut txns = vec![];
                let mut tx_hashes = vec![];
                for mut tx in txs {
                    let tx_gas = match self.chain.provider.estimate_gas(&tx, None)
                        .await
                        .map_err(|e| anyhow!("fail to estimate gas: {e}")) {
                        Ok(gas) => gas,
                        // it may be impossible to simulate certain transactions (e.g. transfer NFT without having ownership yet)
                        // todo: fallback mechanism needed
                        Err(_) => U256::from(110_000)
                    };

                    gas_total += tx_gas;

                    tx.set_chain_id(self.chain.chain_id())
                        .set_gas(tx_gas)
                        .set_gas_price(gas_price);
                    tx_hashes.push(tx.sighash());
                    txns.push(tx);
                }

                (txns, tx_hashes, gas_total)
            }
        };

        self.txns = txns;

        let (tx, _) = {
            let fee = (tx_gas * gas_price).as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;

            let local_addr = self.wallet.address();
            let s1 = self
                .chain
                .address_from_pk(self.s1.shared_pk.as_ref().unwrap());

            self
                .chain
                .compose_tx(local_addr, s1, self.amount + fee, Some(gas_price))
                .expect("tx to compose")
        };
        let _ = self.chain.send(tx, &self.wallet).await?;

        // (c) Alice encloses for time t_b her local key share x^S1_p2 into commitment C_b and proof π_b.
        let refund_vtc = self.time_lock.lock(
            &self.s1.key_share.as_ref().unwrap().secret_share,
            &self.refund_after
        );

        // (d) Using local shares x^S1_p2 and x^S2_p2 Alice computes `Sign::P2::Msg2` for h_b, h_a respectively
        let pre_sig1 = {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } =
                self.s1.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &commitments,
                ek,
                c_key,
                &self.s1.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &tx_hash,
            )
                .map_err(|e| anyhow!("error in signing round 2: {e}"))
        }?;

        let pre_sigs2 = tx_hashes.into_iter().map(|h| {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } =
                self.s2.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &commitments,
                ek,
                c_key,
                &self.s2.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &BigInt::from_bytes(&h.to_fixed_bytes()[..]),
            )
                .map_err(|e| anyhow!("error in signing round 2: {e}"))
        }).collect::<Result<Vec<_>, _>>()?;

        Ok(LockMsg2 {
            s1: pre_sig1,
            s2: pre_sigs2,
            refund_vtc,
            tx_gas: gas_total,
            gas_price
        })
    }

    pub async fn complete(&mut self, swap_adaptors: crate::maker::SwapMsg) -> anyhow::Result<()> {
        // (a) Alice decrypts σ′ a using key y to get a valid signature σ_a,
        let sigs = swap_adaptors.into_iter().map(|adaptor| sign::decrypt_signature(
            &adaptor,
            &self.adaptor_wit,
            self.sign_p1_pub_share.as_ref().unwrap(),
            &self.sign_local.as_ref().unwrap().k3_pair,
        )).collect_vec();

        // which she then broadcasts on-chain along with the transaction, that transfers α coins from S2 to Da.
        let from = self.s2_address();
        for (tx, sig) in self.txns.clone().into_iter().zip(sigs) {
            self.chain.send_signed(from, tx, &sig).await?;
        }

        Ok(())
    }

    pub fn s2_address(&self) -> Address {
        self
            .chain
            .address_from_pk(self.s2.shared_pk.as_ref().unwrap())
    }
}
