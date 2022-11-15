use std::net::SocketAddr;
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures_util::{SinkExt, TryFutureExt};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{routes, State};
use std::str::FromStr;

use tracing::{info_span, Instrument};
use crate::maker::MakerMsg;
use crate::{maker, taker};

struct Runtime {
    tx: mpsc::Sender<MakerMsg>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LockRequest {
    pub target_address: String,
    pub amount: f64,
    pub msg: taker::LockMsg1
}

#[post("/setup", data = "<req>")]
async fn setup(state: &State<Runtime>, req: Json<taker::SetupMsg>) -> Result<Json<maker::SetupMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerMsg::Setup { msg: req.0, resp_tx: tx })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx.instrument(info_span!("maker::setup")).await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[post("/lock", data = "<req>")]
async fn lock(
    state: &State<Runtime>,
    req: Json<LockRequest>
) -> Result<Json<maker::LockMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    let target_address= Address::from_str(&req.target_address)
        .map_err(|_e| status::Custom(Status::BadRequest, "invalid target address".to_string()))?;
    state
        .tx
        .clone()
        .send(MakerMsg::Lock {
            target_address,
            amount: req.0.amount,
            msg: req.0.msg,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx
        .instrument(info_span!("maker::lock"))
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[post("/swap", data = "<req>")]
async fn swap(
    state: &State<Runtime>,
    req: Json<taker::LockMsg2>
) -> Result<Json<maker::SwapMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerMsg::Swap {
            msg: req.0,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx
        .instrument(info_span!("maker::swap"))
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[allow(unused_must_use)]
pub async fn serve(to_runtime: mpsc::Sender<maker::MakerMsg>, addr: String) {
    let addr: SocketAddr = addr.parse().expect("valid address");
    let mut config = rocket::Config::default();
    config.address = addr.ip();
    config.port = addr.port();
    config.shutdown.ctrlc = true;
    config.shutdown.force = true;

    rocket::build()
        .manage(Runtime {
            tx: to_runtime,
        })
        .mount("/", routes![setup, lock, swap])
        .launch()
        .await
        .expect("expect server to run");
}
