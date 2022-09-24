use anyhow::anyhow;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use ethers::prelude::*;
use htlp::{lhp, ToBigUint};
use two_party_adaptor::{party_one, party_two};
use two_party_adaptor::party_two::{EcKeyPair, keygen, sign};
use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;

pub const SALT_STRING: &[u8] = &[75, 90, 101, 110];

pub struct Taker {
    address_to: Address,
    amount: f64,

    first_account: Party2SharedAccountState,
    second_account: Party2SharedAccountState,

    sign_p1_pub_share: Option<Point<Secp256k1>>,
    sign_local: Option<sign::PreSignRound1Local>,
    sign_share: Option<EcKeyPair>,
    adaptor_wit: Scalar<Secp256k1>,

    tx: Option<TypedTransaction>,
    refund_pzl: Option<htlp::structures::Puzzle>,

    chain_provider: Ethereum,
    wallet: LocalWallet,

    lhp_params: htlp::structures::Params,
}

#[derive(Default)]
struct Party2SharedAccountState {
    key_share: Option<EcKeyPair>,
    key_p1_msg1: Option<party_one::keygen::KeyGenMsg2>,
    shared_pk: Option<Point<Secp256k1>>,
}

#[serde(crate = "rocket::serde")]
pub type SetupMsg = (keygen::KeyGenMsg1, keygen::KeyGenMsg1);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct LockMsg1 {
    pub commitment: sign::PreSignMsg1,
    pub share_vtc: htlp::structures::Puzzle,
}

#[serde(crate = "rocket::serde")]
pub type LockMsg2 = (sign::PreSignMsg2, sign::PreSignMsg2);

impl Taker
{
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        address_to: Address,
        amount: f64,
    ) -> Self {
        let lhp_params = lhp::setup::setup(20, 1.to_biguint().unwrap());

        Self {
            address_to,
            amount,
            first_account: Default::default(),
            second_account: Default::default(),
            sign_p1_pub_share: Default::default(),
            sign_local: Default::default(),
            sign_share: Default::default(),
            adaptor_wit: Scalar::<Secp256k1>::random(),
            tx: None,
            refund_pzl: None,
            chain_provider,
            wallet,
            lhp_params,
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
        let _ = self.refund_pzl.insert(msg.refund_vtc);

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

        let local_addr = self.wallet.address();
        let shared_addr2 = self.chain_provider.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());
        let (tx, _) = self.chain_provider.compose_tx(local_addr, shared_addr2, self.amount+0.1).expect("tx to compose");
        let _ = self.chain_provider.send(tx, &self.wallet).await?;

        let refund_witness = self.first_account.key_share.as_ref().unwrap().export();
        let share_vtc = lhp::generate::gen(
            &self.lhp_params,
            htlp::BigUint::from_bytes_be(&*refund_witness.to_bytes()),
        );

        let (res, local) = sign::first_message(&self.adaptor_wit);
        let _ = self.sign_local.insert(local); // todo: ensure that it's fine to reuse k2 for multiple txns

        return Ok(LockMsg1 {
            commitment: res,
            share_vtc
        })
    }

    pub fn lock(&mut self, msg: crate::maker::LockMsg1) -> anyhow::Result<LockMsg2> {
        let _ = self.sign_p1_pub_share.insert(msg.commitments.public_share.clone());
        let shared_addr2 = self.chain_provider.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());

        let (tx, tx_hash) = self.chain_provider.compose_tx(shared_addr2, self.address_to, self.amount).expect("tx to compose");
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

    pub async fn complete(&mut self, swap_adaptor: crate::maker::LockMsg2) -> anyhow::Result<H256> {
        let shared_addr2 = self.chain_provider.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());
        // let (tx, hash) = self.chain_provider.compose_tx(shared_addr2, self.address_to, self.amount).expect("tx to compose");
        //
        // println!("{hash}");
        let sig = sign::decrypt_signature(&swap_adaptor, &self.adaptor_wit, self.sign_p1_pub_share.as_ref().unwrap(), &self.sign_local.as_ref().unwrap().k3_pair);

        self.chain_provider.send_signed(self.tx.take().unwrap(), &sig).await
    }
}
