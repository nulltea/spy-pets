use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures_util::{SinkExt, TryFutureExt};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{routes, State};
use std::str::FromStr;
use crate::maker::MakerMsg;
use crate::{maker, taker};

struct Runtime {
    tx: mpsc::Sender<MakerMsg>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct InfoResponse {
    price: f64,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Step1Response {
    ciphertext: Vec<u8>,
    proof_of_encryption: Vec<u8>,
    data_pk: String,
    address: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Step3Request<'r> {
    pub_key: &'r str,
    enc_sig: &'r str,
}

#[post("/setup", data = "<req>")]
async fn setup(state: &State<Runtime>, req: taker::SetupMsg) -> Result<Json<maker::SetupMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerMsg::Setup { msg: req, resp_tx: tx })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx.await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[post("/lock1", data = "<req>")]
async fn lock1(
    state: &State<Runtime>,
    req: taker::LockMsg1
) -> Result<Json<maker::LockMsg1>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerMsg::Lock1 {
            amount: 1.0,
            msg: req,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[post("/lock2", data = "<req>")]
async fn lock2(
    state: &State<Runtime>,
    req: taker::LockMsg2
) -> Result<Json<maker::LockMsg2>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerMsg::Lock2 {
            msg: req,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[allow(unused_must_use)]
pub async fn serve(to_runtime: mpsc::Sender<SellerMsg>) {
    rocket::build()
        .manage(Runtime {
            tx: to_runtime,
        })
        .mount("/", routes![setup, lock1, lock2])
        .launch()
        .await
        .expect("expect server to run");
}
