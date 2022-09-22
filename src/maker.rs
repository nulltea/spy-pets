use anyhow::anyhow;
use async_std::prelude::StreamExt;
use backoff::ExponentialBackoff;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Secp256k1};
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use two_party_adaptor::party_one::{keygen, EcKeyPair, CommWitness, PaillierKeyPair, Party1Private, sign, EphEcKeyPair};
use two_party_adaptor::{EncryptedSignature, party_two};
use htlp::lhp;
use crate::ethereum::Ethereum;
use crate::wallet::LocalWallet;

pub struct Maker {
    address_to: Address,

    from_takers: mpsc::Receiver<MakerMsg>,
    first_account: Party1SharedAccountState,
    second_account: Party1SharedAccountState,

    sign_share: Option<EphEcKeyPair>,
    tx: Option<TransactionRequest>,
    // swap_adaptor: Option<EncryptedSignature>,

    chain: Ethereum,
    wallet: LocalWallet,

    refund_pzl: Option<htlp::structures::Puzzle>,
    lhp_params: htlp::structures::Params,
}

#[derive(Default)]
struct Party1SharedAccountState {
    key_share: Option<EcKeyPair>,
    key_comm_wit: Option<CommWitness>,
    key_paillier: Option<PaillierKeyPair>,
    key_private: Option<Party1Private>,
    shared_pk: Option<Point<Secp256k1>>,
}

pub type SetupMsg1 = (keygen::KeyGenMsg1, keygen::KeyGenMsg1);
pub struct SetupMsg2 {
    pub account1: keygen::KeyGenMsg2,
    pub account2: keygen::KeyGenMsg2,
    pub refund_vtc: htlp::structures::Puzzle,
}
pub struct LockMsg1 {
    pub commitments: sign::PreSignMsg1,
    pub tx_hash: BigInt,
}
pub type LockMsg2 = EncryptedSignature;

pub enum MakerMsg {
    Setup1 {
        resp_tx: oneshot::Sender<anyhow::Result<SetupMsg1>>,
    },
    Setup2 {
        msg: crate::taker::SetupMsg1,
        resp_tx: oneshot::Sender<anyhow::Result<SetupMsg2>>,
    },
    Lock1 {
        amount: f64,
        msg: crate::taker::SetupMsg2,
        resp_tx: oneshot::Sender<anyhow::Result<LockMsg1>>,
    },
    Lock2 {
        msg1: crate::taker::LockMsg1,
        msg2: crate::taker::LockMsg2,
        resp_tx: oneshot::Sender<anyhow::Result<LockMsg2>>,
    }
}

impl Maker {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        address_to: Address,
    ) -> anyhow::Result<(Self, mpsc::Sender<MakerMsg>)> {
        let (to_maker, from_takers) = mpsc::channel(1);
        let lhp_params = lhp::setup::setup(20, 18.to_biguint().unwrap());

        Ok((
            Self {
                address_to,
                from_takers,
                chain: chain_provider,
                wallet,
                first_account: Default::default(),
                second_account: Default::default(),
                sign_share: Default::default(),
                refund_pzl: Default::default(),
                lhp_params,
                tx: None
            },
            to_maker,
        ))
    }

    pub async fn run(mut self) {
        loop {
            if let Some(msg) = self.from_takers.next().await {
                match msg {
                    MakerMsg::Setup1 { resp_tx } => {
                        let (res1, comm_witness, key_share) = keygen::first_message();
                        let _ = self.first_account.key_share.insert(key_share);
                        let _ = self.first_account.key_comm_wit.insert(comm_witness);

                        let (res2, comm_witness, key_share) = keygen::first_message();
                        let _ = self.second_account.key_share.insert(key_share);
                        let _ = self.second_account.key_comm_wit.insert(comm_witness);


                        resp_tx.send(Ok((res1, res2)))
                    }
                    MakerMsg::Setup2 { msg, resp_tx } => {
                        let (msg1, msg2) = msg;

                        let account1 = {
                            let key_share = self.first_account.key_share.as_ref().unwrap();
                            let (res, paillier, private) = keygen::second_message(
                                self.first_account.key_comm_wit.unwrap(),
                                key_share,
                                &msg1.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg1.public_share);
                            let _ = self.first_account.key_paillier.insert(paillier);
                            let _ = self.first_account.key_private.insert(private);
                            let _ = self.first_account.shared_pk.insert(shared_pk);
                            res
                        };

                        let account2 = {
                            let key_share = self.second_account.key_share.as_ref().unwrap();
                            let (res, paillier, private) = keygen::second_message(
                                self.second_account.key_comm_wit.unwrap(),
                                key_share,
                                &msg2.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg2.public_share);
                            let _ = self.second_account.key_paillier.insert(paillier);
                            let _ = self.second_account.key_private.insert(private);
                            let _ = self.second_account.shared_pk.insert(shared_pk);
                            res
                        };

                        let refund_witness = self.first_account.key_share.as_ref().unwrap().export();
                        let refund_vtc = lhp::generate::gen(&self.lhp_params, refund_witness);

                        resp_tx.send(Ok(SetupMsg2{
                            account1,
                            account2,
                            refund_vtc
                        }))
                    }
                    MakerMsg::Lock1 { amount, msg, resp_tx } => {
                        let _ = self.refund_pzl.insert(msg.share_vtc);

                        let local_addr = self.wallet.address();
                        let shared_addr1 = self.chain.address_from_pk(self.first_account.shared_pk.as_ref().unwrap());
                        let (tx, _) = self.chain.compose_tx(local_addr, shared_addr1, amount).expect("tx to compose");
                        let _ = self.chain.send(tx, &self.wallet).await;

                        let (commitments, eph_share) = sign::first_message();
                        let _ = self.sign_share.insert(eph_share); // todo: ensure that it's fine to reuse k1 for multiple txns

                        let (tx, tx_hash) = self.chain.compose_tx(shared_addr1, self.address_to, amount).expect("tx to compose");
                        let _ = self.tx.insert(tx);

                        resp_tx.send(Ok(LockMsg1{
                            commitments,
                            tx_hash: BigInt::from_bytes(&*tx_hash.to_fixed_bytes())
                        }))
                    }
                    MakerMsg::Lock2 {msg1, msg2, resp_tx } => {
                        sign::verify_commitments_and_dlog_proof(&msg1, &msg2.0).expect("expect valid");
                        sign::verify_commitments_and_dlog_proof(&msg1, &msg2.1).expect("expect valid");

                        let adaptor1 = sign::second_message(
                            &self.first_account.key_private.unwrap(),
                            &self.first_account.key_share.unwrap().public_share,
                            &msg2.0.c3,
                            &self.sign_share.unwrap(),
                            &msg2.0.k2.public_share,
                            &msg2.0.k3_pair.public_share,
                            &msg2.0.message
                        );
                        // let _ = self.swap_adaptor.insert(adaptor1);

                        let adaptor2 = sign::second_message(
                            &self.second_account.key_private.unwrap(),
                            &self.second_account.key_share.unwrap().public_share,
                            &msg2.1.c3,
                            &self.sign_share.unwrap(),
                            &msg2.1.k2.public_share,
                            &msg2.1.k3_pair.public_share,
                            &msg2.1.message
                        );

                        let _ = resp_tx.send(Ok(adaptor2.clone()));

                        // Complete:
                        let hash = H256::from_slice(&*msg2.0.message.to_bytes());
                        let signature = backoff::future::retry(ExponentialBackoff::default(), || async {
                            match self.chain.get_signature(hash).await {
                                Ok(Some(sig)) => Ok(sig),
                                Ok(None) => Err(backoff::Error::transient(anyhow!("tx not found"))),
                                Err(e) => Err(backoff::Error::permanent(e)),
                            }
                        }).await?;

                        let decryption_key = sign::recover_witness(adaptor2, &signature);

                        let signature = party_two::sign::decrypt_signature(
                            &adaptor1, &decryption_key,
                            &self.sign_share.unwrap().public_share,
                            &msg2.0.r3_pair,
                        );

                        self.chain.send_signed(self.tx.unwrap(), &signature).await
                    }
                }
            }
        }
    }
}
