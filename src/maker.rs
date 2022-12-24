use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::Duration;

use crate::ethereum::Ethereum;
use crate::types::transaction::eip2718::TypedTransaction;
use crate::{vtc, WEI_IN_ETHER};
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
use itertools::Itertools;
use crate::vtc::TimeLock;

pub struct Maker<TL: TimeLock> {
    secondary_address: Address,
    refund_after: Duration,

    from_takers: mpsc::Receiver<MakerRequest>,
    sessions: HashMap<String, SessionState>,

    chain: Ethereum,
    wallet: LocalWallet,
    time_lock: TL
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
    pub s1: (keygen::KeyGenMsg1, keygen::KeyGenMsg2),
    pub s2: (keygen::KeyGenMsg1, keygen::KeyGenMsg2),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockMsg {
    pub commitments: sign::PreSignMsg1,
    pub refund_vtc: vtc::VTC,
    pub tx_hash: BigInt,
    pub tx_gas: U256,
    pub gas_price: U256,
}
pub type SwapMsg = Vec<EncryptedSignature>;

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

impl<TL: TimeLock> Maker<TL> {
    pub fn new(
        chain_provider: Ethereum,
        wallet: LocalWallet,
        secondary_address: Address,
        time_lock: TL,
        refund_after: Duration
    ) -> anyhow::Result<(Self, mpsc::Sender<MakerRequest>)> {
        let (to_maker, from_takers) = mpsc::channel(1);

        Ok((
            Self {
                secondary_address,
                refund_after,
                from_takers,
                chain: chain_provider,
                wallet,
                sessions: Default::default(),
                time_lock,
            },
            to_maker,
        ))
    }

    pub async fn run(mut self) {
        let mut vtc_tasks = FuturesUnordered::new();
        let mut swap_completions = FuturesUnordered::new();

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

                        /// Bob takes P1’s role in Lindell'17 and computes `KeyGen::P1::Msg1` for S1, S2.
                        let s1 = {
                            let (res1, comm_witness, key_share) = keygen::first_message();
                            let _ = session.s1.key_share.insert(key_share);
                            let _ = session.s1.key_comm_wit.insert(comm_witness.clone());

                            let key_share = session.s1.key_share.as_ref().unwrap();

                            /// Using the tuple of `KeyGen::P2::Msg1` received from Alice,
                            /// he also computes `KeyGen::P1::Msg2` for S1, S2.
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

                        let s2 = {
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

                        // (b) Bob sends tuple of `KeyGen::P1::Msg1`, tuple of `KeyGen::P1::Msg2` to Alice.
                        resp_tx.send(Ok(SetupMsg {
                            s1,
                            s2,
                        })).unwrap();
                    }
                    MakerRequest::Lock { remote_addr, msg, resp_tx } => {
                        let session = match self.sessions.get_mut(&remote_addr) {
                            Some(e) => e,
                            None => panic!("unexpected message order")
                        };
                        let _ = session.sign_p2_commit.insert(msg);

                        let gas_price = self.chain.provider.get_gas_price().await.unwrap();

                        // (a) Bob computes hash h_b of the transaction that transfer α coins from S1 into D_b
                        let s1 = self.chain.address_from_pk(session.s1.shared_pk.as_ref().unwrap());
                        let (tx, tx_hash) = self.chain.compose_tx(s1, self.secondary_address, session.requested_amount, Some(gas_price)).expect("tx to compose");
                        let tx_gas = self.chain.provider.estimate_gas(&tx, None).await.unwrap();
                        let _ = session.tx.insert(tx);

                        // (b) Bob encloses for time ta his local key share x^S1_p1 into commitment C_a and proof π_a according to VTC scheme.
                        let refund_vtc = self.time_lock.lock(
                            &session.s1.key_share.as_ref().unwrap().secret_share,
                            &self.refund_after,
                        );

                        // (c) Bob compute `Sign::P1::Msg1` and sends it to Alice it along with C_b, π_b, and h_b.
                        let (commitments, eph_share) = sign::first_message();
                        let _ = session.sign_share.insert(eph_share); // todo: ensure that it's fine to reuse k1 for multiple txns


                        resp_tx.send(Ok(LockMsg {
                            commitments,
                            refund_vtc,
                            tx_hash: BigInt::from_bytes(&tx_hash.to_fixed_bytes()[..]),
                            tx_gas,
                            gas_price,
                        })).unwrap();
                    }
                    MakerRequest::Swap { remote_addr, msg, resp_tx } => {
                        let mut session = match self.sessions.remove(&remote_addr) {
                            Some(e) => e,
                            None => panic!("unexpected message order")
                        };

                        let crate::taker::LockMsg2{
                            s1,
                            s2,
                            refund_vtc,
                            tx_gas,
                            gas_price,
                        } = msg;

                        // (a) Bob veriﬁes dlog proofs
                        let prev_commit = session.sign_p2_commit.take().unwrap();
                        sign::verify_commitments_and_dlog_proof(&prev_commit, &s1.comm_witness).expect("expect valid");
                        s2.iter().map(|m| sign::verify_commitments_and_dlog_proof(&prev_commit, &m.comm_witness).expect("expect valid"));

                        // (b) Bob veriﬁes proof π_b;
                        assert!(refund_vtc.verify(
                            &session.s1.key_share.as_ref().unwrap().secret_share,
                            session.s1.shared_pk.as_ref().unwrap()
                        ), "invalid refund VTC");

                        // Unlocks VTC and handles refund.
                        {
                            let amount = session.requested_amount;
                            let x_p1 = session.s2.key_share.as_ref().unwrap().secret_share.clone();
                            let addr = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                            vtc_tasks.push(tokio::task::spawn(async move {
                                (
                                    x_p1,
                                    addr,
                                    amount,
                                    refund_vtc.unlock().await.unwrap(),
                                )
                            }));
                        }

                        // (c) Bob deposits α coins to S2.
                        let local_addr = self.wallet.address();
                        let s2_addr = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                        let (tx, _) = {
                            let fee = (tx_gas * gas_price).as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;

                            self.chain.compose_tx(local_addr, s2_addr, session.requested_amount + fee, Some(gas_price)).expect("tx to compose")
                        };
                        let _ = self.chain.send(tx, &self.wallet).await;

                        // Using local shares x^S1_b and x^S2_b he computes σ′_b,σ′_a (pre-signatures) for h_b,h_a respectively:
                        let adaptors2 = s2.iter().map(|m| sign::second_message(
                            session.s2.key_private.as_ref().unwrap(),
                            &session.s2.key_share.as_ref().unwrap().public_share,
                            &m.c3,
                            session.sign_share.as_ref().unwrap(),
                            &m.comm_witness.public_share,
                            &m.K3,
                            &m.message
                        )).collect_vec();

                        let first_adaptor = adaptors2.first().unwrap().clone();

                        let _ = resp_tx.send(Ok(adaptors2));

                        // Complete:
                        // (b) Bob downloads σ_a to recover witness y from σ′_a
                        let s2_addr = self.chain.address_from_pk(session.s2.shared_pk.as_ref().unwrap());
                        let signature = self.chain.listen_for_signature(s2_addr).await.unwrap();

                        // decrypts σ′_b using key y to get a valid signature σ_b,
                        let decryption_key = sign::recover_witness(first_adaptor, &signature);

                        // which he then broadcasts on-chain along with the transaction that transfers α coins from S1 to Db.
                        swap_completions.push(tokio::task::spawn(async move {
                            let k3 = match s1.k3.clone() {
                                crate::taker::OptionalDelay::Plain(k3) => k3,
                                crate::taker::OptionalDelay::Delayed(vtc) => {
                                    info!("delaying withdrawal...");
                                    vtc.unlock().await.unwrap()
                                },
                            };

                            (
                                sign::second_message(
                                    session.s1.key_private.as_ref().unwrap(),
                                    &session.s1.key_share.as_ref().unwrap().public_share,
                                    &s1.c3,
                                    session.sign_share.as_ref().unwrap(),
                                    &s1.comm_witness.public_share,
                                    &s1.K3,
                                    &s1.message
                                ),
                                decryption_key,
                                session,
                                k3,
                            )
                        }));
                    }
                    _ => {}
                },
                vtc_openning = vtc_tasks.select_next_some() => {
                    // Refund path:
                    // (a) After time t_b Bob opens timed commitment C_b and acquires Alice’s key share x^S2_p2
                    if let Ok((x_p1, addr, amount, x_p2)) = vtc_openning {
                        let gas_price = self.chain.provider.get_gas_price().await.unwrap();
                        let balance = self.chain.provider.get_balance(addr, None).await.unwrap().as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
                        if balance > amount {
                            // multiples by x^S2_p1 to get valid key x^S2.
                            let full_sk = &x_p1 * &x_p2;
                            let fee = (U256::from(21000) * gas_price).as_u64() as f64 / WEI_IN_ETHER.as_u64() as f64;
                            let signer = LocalWallet::from(SigningKey::from_bytes(&*full_sk.to_bytes()).unwrap());
                            // (b) Having x^S2 , Bob can now sign the transaction to transfer α from S2 to other account of his choice.
                            let (tx, _) = self.chain.compose_tx(addr, self.wallet.address(), balance-fee, Some(gas_price)).unwrap();
                            self.chain.send(tx, &signer).await.unwrap();
                            warn!("swap failed, funds were refunded to {}", self.wallet.address());
                        } else {
                            info!("timeout passed, all good.");
                        }
                    }
                }
                res = swap_completions.select_next_some() =>  {
                    if let Ok((adaptor1, decryption_key, mut session, k3)) = res {
                        let signature = party_two::sign::decrypt_signature(
                            &adaptor1, &decryption_key,
                            &session.sign_share.as_ref().unwrap().public_share,
                            &k3,
                        );

                        let s1 = self.chain.address_from_pk(session.s1.shared_pk.as_ref().unwrap());
                        self.chain.send_signed(s1, session.tx.take().unwrap(), &signature).await.unwrap();

                        let wei = self.chain.provider.get_balance(self.secondary_address, None).await.unwrap();
                        let eth = wei / WEI_IN_ETHER;
                        info!("balance of {} is {} ETH", self.secondary_address, eth.as_u64());
                    }
                }
            }
        }
    }
}
