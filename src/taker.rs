use anyhow::anyhow;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use ethers::prelude::*;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::utils::WEI_IN_ETHER;
use htlp::{lhp, ToBigUint};
use serde::{Serialize, Deserialize};
use two_party_adaptor::{party_one, party_two};
use two_party_adaptor::party_two::{EcKeyPair, keygen, sign};
use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;

pub const SALT_STRING: &[u8] = &[75, 90, 101, 110];

#[derive(Clone)]
pub struct Taker {
    amount: f64,
    refund_time_param: u64,

    first_account: Party2SharedAccountState,
    second_account: Party2SharedAccountState,

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockMsg1 {
    pub commitment: sign::PreSignMsg1,
    pub vtc_params: htlp::structures::Params,
    pub refund_vtc: htlp::structures::Puzzle,
}

pub type LockMsg2 = (sign::PreSignMsg2, sign::PreSignMsg2);

impl Taker
{
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        amount: f64,
        refund_time_param: u64,
    ) -> Self {

        Self {
            amount,
            refund_time_param,
            first_account: Default::default(),
            second_account: Default::default(),
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
            let _ = self.first_account.key_share.insert(key_share);
            res
        };

        let msg2 = {
            let (res, key_share) = keygen::first_message();
            let _ = self.second_account.key_share.insert(key_share);
            res
        };

        return Ok((msg1, msg2))
    }

    pub async fn setup2(&mut self, msg: crate::maker::SetupMsg) -> anyhow::Result<LockMsg1> {
        let _ = self.first_account.key_p1_msg1.insert(msg.account1.1.clone());
        let _ = self.second_account.key_p1_msg1.insert(msg.account2.1.clone());

        {
            keygen::second_message(
                &msg.account1.0,
                &msg.account1.1,
                SALT_STRING,
            ).map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.first_account.key_share.as_ref().unwrap(),
                &msg.account1.0.public_share
            );
            let _ = self.first_account.shared_pk.insert(shared_pk);
        };

        {
            keygen::second_message(
                &msg.account2.0,
                &msg.account2.1,
                SALT_STRING,
            ).map_err(|_| anyhow!("verification failed"))?;
            let shared_pk = keygen::compute_pubkey(
                self.second_account.key_share.as_ref().unwrap(),
                &msg.account2.0.public_share);
            let _ = self.second_account.shared_pk.insert(shared_pk);
        };

        {
            let me = self.clone();
            let pp = msg.vtc_params.clone();
            let vtc = msg.refund_vtc.clone();
            tokio::task::spawn_blocking(move || {
                let dlog = lhp::solve::solve(&pp, &vtc);
                tokio::task::spawn(async move {
                    let addr = me.chain.address_from_pk(me.second_account.shared_pk.as_ref().unwrap());
                    let balance = me.chain.provider.get_balance(addr, None)
                        .await.unwrap().as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
                    if balance > me.amount {
                        let sk1 = Scalar::from_bigint(&BigInt::from_bytes(&dlog.to_bytes_be()));
                        let full_sk = &sk1 * &me.second_account.key_share.as_ref().unwrap().secret_share;
                        let signer = LocalWallet::from(SigningKey::from_bytes(&*full_sk.to_bytes()).unwrap());
                        let (tx, _) = me.chain.compose_tx(addr, me.wallet.address(), me.amount).unwrap();
                        me.chain.send(tx, &signer).await.unwrap();
                        println!("swap failed, funds were refunded to {}", me.wallet.address());
                    } else {
                        println!("timeout passed, all good.");
                    }
                });
            });
        }

        let local_addr = self.wallet.address();
        let shared_addr2 = self.chain.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());
        let (tx, _) = self.chain.compose_tx(local_addr, shared_addr2, self.amount+0.1).expect("tx to compose");
        let _ = self.chain.send(tx, &self.wallet).await?;

        let vtc_params = lhp::setup::setup(
            two_party_adaptor::SECURITY_BITS as u64,
            self.refund_time_param.to_biguint().unwrap()
        );
        let refund_witness = self.first_account.key_share.as_ref().unwrap().secret_share.to_bigint();
        let refund_vtc = lhp::generate::gen(
            &vtc_params,
            htlp::BigUint::from_bytes_be(&*refund_witness.to_bytes()),
        );

        let (res, local) = sign::first_message(&self.adaptor_wit);
        let _ = self.sign_local.insert(local); // todo: ensure that it's fine to reuse k2 for multiple txns

        return Ok(LockMsg1 {
            commitment: res,
            vtc_params,
            refund_vtc
        })
    }

    pub fn lock(&mut self, msg: crate::maker::LockMsg) -> anyhow::Result<LockMsg2> {
        let _ = self.sign_p1_pub_share.insert(msg.commitments.public_share.clone());
        let shared_addr2 = self.chain.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());

        let (tx, tx_hash) = self.chain.compose_tx(shared_addr2, msg.target_address, self.amount).expect("tx to compose");
        let _ = self.tx.insert(tx);

        let pre_sig1 = {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } = self.first_account.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &msg.commitments,
                ek,
                c_key,
                &self.first_account.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &msg.commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &msg.tx_hash,
            ).map_err(|e| anyhow!("error in signing round 2: {e}"))
        }?;

        let pre_sig2 = {
            let party_one::keygen::KeyGenMsg2 { ek, c_key, .. } = self.second_account.key_p1_msg1.as_ref().unwrap();

            sign::second_message(
                self.sign_local.as_ref().unwrap().k2_commit.clone(),
                &msg.commitments,
                 ek,
                c_key,
                &self.second_account.key_share.as_ref().unwrap(),
                &self.sign_local.as_ref().unwrap().k2_pair,
                &msg.commitments.public_share,
                &self.sign_local.as_ref().unwrap().k3_pair,
                &BigInt::from_bytes(&tx_hash.to_fixed_bytes()[..]),
            ).map_err(|e| anyhow!("error in signing round 2: {e}"))
        }?;

        Ok((pre_sig1, pre_sig2))
    }

    pub async fn complete(&mut self, swap_adaptor: crate::maker::SwapMsg) -> anyhow::Result<H256> {
        let sig = sign::decrypt_signature(&swap_adaptor, &self.adaptor_wit, self.sign_p1_pub_share.as_ref().unwrap(), &self.sign_local.as_ref().unwrap().k3_pair);

        self.chain.send_signed(self.tx.take().unwrap(), &sig).await
    }
}
