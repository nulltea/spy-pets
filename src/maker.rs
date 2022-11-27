use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;
use crate::WEI_IN_ETHER;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use futures_util::stream::FuturesUnordered;
use futures_util::{select, FutureExt, SinkExt};
use htlp::{lhp, ToBigUint};
use serde::{Deserialize, Serialize};
use tracing::log::{info, warn};
use two_party_adaptor::party_one::{
    keygen, sign, CommWitness, EcKeyPair, EphEcKeyPair, PaillierKeyPair, Party1Private,
};
use two_party_adaptor::{party_two, EncryptedSignature};

pub struct Maker {
    secondary_address: Address,
    refund_time_param: u64,

    from_takers: mpsc::Receiver<MakerRequest>,
    sessions: HashMap<String, SessionState>,

    chain: Ethereum,
    wallet: LocalWallet,
}

struct SessionState {
    requested_amount: f64,

    s1: Party1SharedAccountState,
    s2: Party1SharedAccountState,

    sign_p2_commit: Option<party_two::sign::PreSignMsg1>,
    sign_share: Option<EphEcKeyPair>,
    tx: Option<TypedTransaction>,
    signature: Option<two_party_adaptor::Signature>,
}

impl SessionState {
    fn new(requested_amount: f64) -> Self {
        Self {
            requested_amount,
            s1: Default::default(),
            s2: Default::default(),
            sign_p2_commit: None,
            sign_share: None,
            tx: None,
            signature: None,
        }
    }
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockMsg {
    pub commitments: sign::PreSignMsg1,
    pub vtc_params: htlp::structures::Params,
    pub refund_vtc: htlp::structures::Puzzle,
    pub tx_hash: BigInt,
    pub tx_gas: U256,
    pub gas_price: U256,
}
pub type SwapMsg = EncryptedSignature;

pub enum MakerRequest {
    Setup {
        remote_addr: String,
        amount: f64,
        msg: crate::taker::SetupMsg,
        resp_tx: oneshot::Sender<anyhow::Result<SetupMsg>>,
    },
    Lock {
        remote_addr: String,
        msg: crate::taker::LockMsg1,
        resp_tx: oneshot::Sender<anyhow::Result<LockMsg>>,
    },
    Swap {
        remote_addr: String,
        msg: crate::taker::LockMsg2,
        resp_tx: oneshot::Sender<anyhow::Result<SwapMsg>>,
    },
}

impl Maker {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        secondary_address: Address,
        refund_time_param: u64,
    ) -> anyhow::Result<(Self, mpsc::Sender<MakerRequest>)> {
        let (to_maker, from_takers) = mpsc::channel(1);

        Ok((
            Self {
                secondary_address,
                refund_time_param,
                from_takers,
                sessions: Default::default(),
                chain: chain_provider,
                wallet,
            },
            to_maker,
        ))
    }

    pub async fn run(mut self) {
        let mut puzzle_tasks = FuturesUnordered::new();
        let mut service_messages = self.from_takers.fuse();

        loop {
            select! {
                msg = service_messages.select_next_some() => match msg {
                    MakerRequest::Setup { remote_addr, amount, msg, resp_tx } => {
                        let session: &mut SessionState = match self.sessions.entry(remote_addr) {
                            Entry::Vacant(e) => e.insert(SessionState::new(amount)),
                            Entry::Occupied(_e) => panic!("unexpected message order")
                        };
                        let (msg1, msg2) = msg;

                        let account1 = {
                            let (res1, comm_witness, key_share) = keygen::first_message();
                            let _ = session.s1.key_share.insert(key_share);
                            let _ = session.s1.key_comm_wit.insert(comm_witness.clone());

                            let key_share = session.s1.key_share.as_ref().unwrap();
                            let (res2, paillier, private) = keygen::second_message(
                                comm_witness,
                                key_share,
                                &msg1.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg1.public_share);
                            let _ = session.s1.key_paillier.insert(paillier);
                            let _ = session.s1.key_private.insert(private);
                            let _ = session.s1.shared_pk.insert(shared_pk);
                            (res1, res2)
                        };

                        let account2 = {
                            let (res1, comm_witness, key_share) = keygen::first_message();
                            let _ = session.s2.key_share.insert(key_share);
                            let _ = session.s2.key_comm_wit.insert(comm_witness.clone());

                            let key_share = session.s2.key_share.as_ref().unwrap();
                            let (res2, paillier, private) = keygen::second_message(
                                comm_witness,
                                key_share,
                                &msg2.d_log_proof,
                            ).expect("d_log invalid");
                            let shared_pk = keygen::compute_pubkey(key_share, &msg2.public_share);
                            let _ = session.s2.key_paillier.insert(paillier);
                            let _ = session.s2.key_private.insert(private);
                            let _ = session.s2.shared_pk.insert(shared_pk);
                            (res1, res2)
                        };

                        resp_tx.send(Ok(SetupMsg {
                            account1,
                            account2,
                        })).unwrap();
                    }
                    MakerRequest::Lock { remote_addr, msg, resp_tx } => {
                        let session = match self.sessions.get_mut(&remote_addr) {
                            Some(e) => e,
                            None => panic!("unexpected message order")
                        };
                        let _ = session.sign_p2_commit.insert(msg);

                        let (commitments, eph_share) = sign::first_message();
                        let _ = session.sign_share.insert(eph_share); // todo: ensure that it's fine to reuse k1 for multiple txns

                        let gas_price = self.chain.provider.get_gas_price().await.unwrap();

                        let s1 = self.chain.address_from_pk(session.s1.shared_pk.as_ref().unwrap());
                        let (tx, tx_hash) = self.chain.compose_tx(s1, self.secondary_address, session.requested_amount, Some(gas_price)).expect("tx to compose");
                        let tx_gas = self.chain.provider.estimate_gas(&tx, None).await.unwrap();
                        let _ = session.tx.insert(tx);

                        let refund_witness = session.s1.key_share.as_ref().unwrap().secret_share.to_bigint();
                        let vtc_params = lhp::setup::setup(
                            two_party_adaptor::SECURITY_BITS as u64,
                            self.refund_time_param.to_biguint().unwrap()
                        );
                        let refund_vtc = lhp::generate::gen(
                            &vtc_params,
                            htlp::BigUint::from_bytes_be(&*refund_witness.to_bytes())
                        );

                        resp_tx.send(Ok(LockMsg {
                            commitments,
                            vtc_params,
                            refund_vtc,
                            tx_hash: BigInt::from_bytes(&tx_hash.to_fixed_bytes()[..]),
                            tx_gas,
                            gas_price,
                        })).unwrap();
                    }
                    MakerRequest::Swap { remote_addr, msg, resp_tx } => {
                        let session = match self.sessions.get_mut(&remote_addr) {
                            Some(e) => e,
                            None => panic!("unexpected message order")
                        };

                        let prev_commit = session.sign_p2_commit.take().unwrap();
                        sign::verify_commitments_and_dlog_proof(&prev_commit, &msg.account1).expect("expect valid");
                        sign::verify_commitments_and_dlog_proof(&prev_commit, &msg.account2).expect("expect valid");

                        // todo: verify VTC

                        {
                            let amount = session.requested_amount;
                            let x_p1 = session.s2.key_share.as_ref().unwrap().secret_share.clone();
                            let addr = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                            let pp = msg.vtc_params.clone();
                            let vtc = msg.refund_vtc.clone();
                            puzzle_tasks.push(tokio::task::spawn_blocking(move ||{
                                (
                                    x_p1,
                                    addr,
                                    amount,
                                    lhp::solve::solve(&pp, &vtc),
                                )
                            }));
                        }

                        let local_addr = self.wallet.address();
                        let s2 = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                        let (tx, _) = {
                            let fee = (msg.tx_gas * msg.gas_price).as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;

                            self.chain.compose_tx(local_addr, s2, session.requested_amount + fee, Some(msg.gas_price)).expect("tx to compose")
                        };
                        let _ = self.chain.send(tx, &self.wallet).await;

                        let adaptor1 = sign::second_message(
                            session.s1.key_private.as_ref().unwrap(),
                            &session.s1.key_share.as_ref().unwrap().public_share,
                            &msg.account1.c3,
                            session.sign_share.as_ref().unwrap(),
                            &msg.account1.comm_witness.public_share,
                            &msg.account1.k3_pair.public_share,
                            &msg.account1.message
                        );

                        let adaptor2 = sign::second_message(
                            session.s2.key_private.as_ref().unwrap(),
                            &session.s2.key_share.as_ref().unwrap().public_share,
                            &msg.account2.c3,
                            session.sign_share.as_ref().unwrap(),
                            &msg.account2.comm_witness.public_share,
                            &msg.account2.k3_pair.public_share,
                            &msg.account2.message
                        );

                        let _ = resp_tx.send(Ok(adaptor2.clone()));

                        // Complete:
                        let s2 = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                        let signature = self.chain.listen_for_signature(s2).await.unwrap();

                        let decryption_key = sign::recover_witness(adaptor2, &signature);

                        let signature = party_two::sign::decrypt_signature(
                            &adaptor1, &decryption_key,
                            &session.sign_share.as_ref().unwrap().public_share,
                            &msg.account1.k3_pair,
                        );

                        self.chain.send_signed(session.tx.take().unwrap(), &signature).await.unwrap();

                        let wei = self.chain.provider.get_balance(self.secondary_address, None).await.unwrap();
                        let eth = wei / WEI_IN_ETHER;
                        info!("balance of {} is {} ETH", self.secondary_address, eth.as_u64());
                    }
                    _ => {}
                },
                puzzle_solution = puzzle_tasks.select_next_some() => {
                    if let Ok((x_p1, addr, amount, dlog)) = puzzle_solution {
                        let gas_price = self.chain.provider.get_gas_price().await.unwrap();
                        let balance = self.chain.provider.get_balance(addr, None).await.unwrap().as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
                        if balance > amount {
                            let dlog: htlp::BigUint = dlog;
                            let x_p2 = Scalar::from_bigint(&BigInt::from_bytes(&dlog.to_bytes_be()));
                            let full_sk = &x_p1 * &x_p2;
                            let fee = (U256::from(21000) * gas_price).as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
                            let signer = LocalWallet::from(SigningKey::from_bytes(&*full_sk.to_bytes()).unwrap());
                            let (tx, _) = self.chain.compose_tx(addr, self.wallet.address(), balance-fee, Some(gas_price)).unwrap();
                            self.chain.send(tx, &signer).await.unwrap();
                            warn!("swap failed, funds were refunded to {}", self.wallet.address());
                        }
                    } else {
                        println!("timeout passed, all good.");
                    }
                }
            }
        }
    }
}
