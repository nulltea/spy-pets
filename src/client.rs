use anyhow::anyhow;





use surf::Url;
use crate::{maker, taker};
use crate::server::LockRequest;

pub struct Client {
    client: surf::Client,
}

impl Client {
    pub fn new<S: AsRef<str>>(server_url: S) -> anyhow::Result<Self> {
        let url = Url::parse(server_url.as_ref())
            .map_err(|e| anyhow!("error parsing server url: {e}"))?;
        let config = surf::Config::new().set_base_url(url).set_timeout(None);
        Ok(Self {
            client: config.try_into()?,
        })
    }

    pub async fn setup(&self, msg: taker::SetupMsg) -> anyhow::Result<maker::SetupMsg> {
        let mut resp = self
            .client
            .post("setup")
            .body_json(&msg).unwrap()
            .await
            .map_err(|e| anyhow!("error requesting setup: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        resp
            .body_json::<maker::SetupMsg>()
            .await
            .map_err(|e| anyhow!("error decoding step1 response: {e}"))
    }

    pub async fn lock(&self, target_address: String, amount: f64, msg: taker::LockMsg1) -> anyhow::Result<maker::LockMsg> {
        let mut resp = self
            .client
            .post("lock")
            .body_json(&LockRequest {
                target_address,
                amount,
                msg
            }).unwrap()
            .await
            .map_err(|e| anyhow!("error requesting setup: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        resp
            .body_json::<maker::LockMsg>()
            .await
            .map_err(|e| anyhow!("error decoding lock response: {e}"))
    }

    pub async fn swap(&self, msg: taker::LockMsg2) -> anyhow::Result<maker::SwapMsg> {
        let mut resp = self
            .client
            .post("swap")
            .body_json(&msg).unwrap()
            .await
            .map_err(|e| anyhow!("error requesting setup: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        resp
            .body_json::<maker::SwapMsg>()
            .await
            .map_err(|e| anyhow!("error decoding swap response: {e}"))
    }
}
