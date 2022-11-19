use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures_util::{SinkExt, TryFutureExt};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{routes, State};
use std::net::SocketAddr;

use crate::maker::MakerRequest;
use crate::{maker, taker};
use tracing::{info_span, Instrument};

struct Runtime {
    tx: mpsc::Sender<MakerRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SetupRequest {
    pub amount: f64,
    pub msg: taker::SetupMsg,
}

#[post("/setup", data = "<req>")]
async fn setup(
    remote_addr: SocketAddr,
    state: &State<Runtime>,
    req: Json<SetupRequest>,
) -> Result<Json<maker::SetupMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerRequest::Setup {
            remote_addr: remote_addr.to_string(),
            amount: req.amount,
            msg: req.0.msg,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let res = rx
        .instrument(info_span!("maker::setup"))
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(res))
}

#[post("/lock", data = "<req>")]
async fn lock(
    remote_addr: SocketAddr,
    state: &State<Runtime>,
    req: Json<taker::LockMsg1>,
) -> Result<Json<maker::LockMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerRequest::Lock {
            remote_addr: remote_addr.to_string(),
            msg: req.0,
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
    remote_addr: SocketAddr,
    state: &State<Runtime>,
    req: Json<taker::LockMsg2>,
) -> Result<Json<maker::SwapMsg>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(MakerRequest::Swap {
            remote_addr: remote_addr.to_string(),
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
pub async fn serve(to_runtime: mpsc::Sender<maker::MakerRequest>, addr: String) {
    let addr: SocketAddr = addr.parse().expect("valid address");
    let mut config = rocket::Config::default();
    config.address = addr.ip();
    config.port = addr.port();
    config.shutdown.ctrlc = true;
    config.shutdown.force = true;

    rocket::build()
        .manage(Runtime { tx: to_runtime })
        .mount("/", routes![setup, lock, swap])
        .launch()
        .await
        .expect("expect server to run");
}
