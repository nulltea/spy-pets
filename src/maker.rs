use anyhow::anyhow;
use backoff::ExponentialBackoff;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Secp256k1};
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use two_party_adaptor::party_one::{keygen, EcKeyPair, CommWitness, PaillierKeyPair, Party1Private, sign, EphEcKeyPair};
use two_party_adaptor::{EncryptedSignature, party_two};
use htlp::{lhp, ToBigUint};
use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;
use serde::{Serialize, Deserialize};
use crate::WEI_IN_ETHER;


pub struct Maker {
    target_address: Address,

    from_takers: mpsc::Receiver<MakerMsg>,
    first_account: Party1SharedAccountState,
    second_account: Party1SharedAccountState,

    sign_p2_commit: Option<party_two::sign::PreSignMsg1>,

    sign_share: Option<EphEcKeyPair>,
    tx: Option<TypedTransaction>,
    signature: Option<two_party_adaptor::Signature>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetupMsg {
    pub account1: (keygen::KeyGenMsg1, keygen::KeyGenMsg2),
    pub account2: (keygen::KeyGenMsg1, keygen::KeyGenMsg2),
    pub refund_vtc: htlp::structures::Puzzle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockMsg {
    pub commitments: sign::PreSignMsg1,
    pub tx_hash: BigInt,
}
pub type SwapMsg = EncryptedSignature;

pub enum MakerMsg {
    Setup {
        msg: crate::taker::SetupMsg,
        resp_tx: oneshot::Sender<anyhow::Result<SetupMsg>>,
    },
    Lock {
        amount: f64,
        msg: crate::taker::LockMsg1,
        resp_tx: oneshot::Sender<anyhow::Result<LockMsg>>,
    },
    Swap {
        msg: crate::taker::LockMsg2,
        resp_tx: oneshot::Sender<anyhow::Result<SwapMsg>>,
    },
}

impl Maker {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        target_address: Address,
    ) -> anyhow::Result<(Self, mpsc::Sender<MakerMsg>)> {
        let (to_maker, from_takers) = mpsc::channel(1);
        let lhp_params = lhp::setup::setup(20, 18.to_biguint().unwrap());

        Ok((
            Self {
                target_address,
                from_takers,
                chain: chain_provider,
                wallet,
                first_account: Default::default(),
                second_account: Default::default(),
                sign_p2_commit:  Default::default(),
                sign_share: Default::default(),
                refund_pzl: Default::default(),
                lhp_params,
                tx: None,
                signature: None
            },
            to_maker,
        ))
    }

    pub async fn run(mut self) {
        loop {
            if let Some(msg) = self.from_takers.next().await {
                match msg {
                    MakerMsg::Setup { msg, resp_tx } => {
                        let (msg1, msg2) = msg;

                        let account1 = {
                            let (res1, comm_witness, key_share) = keygen::first_message();
                            let _ = self.first_account.key_share.insert(key_share);
                            let _ = self.first_account.key_comm_wit.insert(comm_witness.clone());

                            let key_share = self.first_account.key_share.as_ref().unwrap();
                            let (res2, paillier, private) = keygen::second_message(
                                comm_witness,
                                key_share,
                                &msg1.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg1.public_share);
                            let _ = self.first_account.key_paillier.insert(paillier);
                            let _ = self.first_account.key_private.insert(private);
                            let _ = self.first_account.shared_pk.insert(shared_pk);
                            (res1, res2)
                        };

                        let account2 = {
                            let (res1, comm_witness, key_share) = keygen::first_message();
                            let _ = self.second_account.key_share.insert(key_share);
                            let _ = self.second_account.key_comm_wit.insert(comm_witness.clone());

                            let key_share = self.second_account.key_share.as_ref().unwrap();
                            let (res2, paillier, private) = keygen::second_message(
                                comm_witness,
                                key_share,
                                &msg2.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg2.public_share);
                            let _ = self.second_account.key_paillier.insert(paillier);
                            let _ = self.second_account.key_private.insert(private);
                            let _ = self.second_account.shared_pk.insert(shared_pk);
                            (res1, res2)
                        };

                        let refund_witness = self.second_account.key_share.as_ref().unwrap().export();
                        let refund_vtc = lhp::generate::gen(
                            &self.lhp_params,
                            htlp::BigUint::from_bytes_be(&*refund_witness.to_bytes())
                        );

                        resp_tx.send(Ok(SetupMsg {
                            account1,
                            account2,
                            refund_vtc
                        })).unwrap();
                    }
                    MakerMsg::Lock { amount, msg, resp_tx } => {
                        let _ = self.refund_pzl.insert(msg.share_vtc);
                        let _ = self.sign_p2_commit.insert(msg.commitment);

                        let local_addr = self.wallet.address();
                        let shared_addr1 = self.chain.address_from_pk(self.first_account.shared_pk.as_ref().unwrap());
                        let (tx, _) = self.chain.compose_tx(local_addr, shared_addr1, amount+0.1).expect("tx to compose");
                        let _ = self.chain.send(tx, &self.wallet).await;

                        let (commitments, eph_share) = sign::first_message();
                        let _ = self.sign_share.insert(eph_share); // todo: ensure that it's fine to reuse k1 for multiple txns

                        let (tx, tx_hash) = self.chain.compose_tx(shared_addr1, self.target_address, amount).expect("tx to compose");
                        let _ = self.tx.insert(tx);

                        resp_tx.send(Ok(LockMsg {
                            commitments,
                            tx_hash: BigInt::from_bytes(&tx_hash.to_fixed_bytes()[..])
                        })).unwrap();
                    }
                    MakerMsg::Swap { msg, resp_tx } => {
                        let prev_commit = self.sign_p2_commit.take().unwrap();
                        sign::verify_commitments_and_dlog_proof(&prev_commit, &msg.0).expect("expect valid");
                        sign::verify_commitments_and_dlog_proof(&prev_commit, &msg.1).expect("expect valid");

                        let adaptor1 = sign::second_message(
                            self.first_account.key_private.as_ref().unwrap(),
                            &self.first_account.key_share.as_ref().unwrap().public_share,
                            &msg.0.c3,
                            self.sign_share.as_ref().unwrap(),
                            &msg.0.comm_witness.public_share,
                            &msg.0.k3_pair.public_share,
                            &msg.0.message
                        );
                        // let _ = self.swap_adaptor.insert(adaptor1);

                        let adaptor2 = sign::second_message(
                            self.second_account.key_private.as_ref().unwrap(),
                            &self.second_account.key_share.as_ref().unwrap().public_share,
                            &msg.1.c3,
                            self.sign_share.as_ref().unwrap(),
                            &msg.1.comm_witness.public_share,
                            &msg.1.k3_pair.public_share,
                            &msg.1.message
                        );

                        let _ = resp_tx.send(Ok(adaptor2.clone()));

                        // Complete:
                        let shared_addr2 = self.chain.address_from_pk(self.second_account.shared_pk.as_ref().unwrap());
                        let signature = self.chain.listen_for_signature(shared_addr2).await.unwrap();

                        let decryption_key = sign::recover_witness(adaptor2, &signature);

                        let signature = party_two::sign::decrypt_signature(
                            &adaptor1, &decryption_key,
                            &self.sign_share.as_ref().unwrap().public_share,
                            &msg.0.k3_pair,
                        );

                        self.chain.send_signed(self.tx.take().unwrap(), &signature).await.unwrap();

                        let wei = self.chain.provider.get_balance(self.target_address, None).await.unwrap();
                        let eth = wei / WEI_IN_ETHER;
                        println!("balance of {} is {} ETH", self.target_address, eth.as_u64());
                    }
                    _ => {}
                }
            }
        }
    }
}
