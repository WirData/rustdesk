use serde::{Deserialize, Serialize};
use std::sync::Once;

use hbb_common::{anyhow, config::Config, log, ResultType};

use crate::hbbs_http::create_http_client_async;

static API_INIT: Once = Once::new();
static mut API_INIT_OK: bool = false;

pub async fn api_login_once() {
    API_INIT.call_once(|| {
        hbb_common::tokio::spawn(async {
            match do_login_and_apply_from_api().await {
                Ok(_) => unsafe { API_INIT_OK = true; },
                Err(e) => {
                    log::warn!("API login failed: {}", e);
                    unsafe { API_INIT_OK = false; }
                }
            }
        });
    });
}

pub fn api_is_ok() -> bool {
    unsafe { API_INIT_OK }
}

// ======================= DTOs =======================

#[derive(Serialize)]
struct ApiAuthRequest {
    username: String,
    password: String,
    id: String,
    uuid: String,
}

#[derive(Deserialize)]
struct ApiRustDeskConfig {
    host: String,
    key: String,
    #[serde(rename = "apiServer")]
    api_server: String,
}

#[derive(Deserialize)]
struct ApiLoginInner {
    token: String,
    key: String,
    #[serde(rename = "rustDeskConfig")]
    rustdesk_config: ApiRustDeskConfig,
    permissions: String,
}

#[derive(Deserialize)]
struct ApiLoginEnvelope {
    #[serde(rename = "login_response")]
    login_response: ApiLoginInner,
}

// ======================= Core =======================

async fn do_login_and_apply_from_api() -> ResultType<()> {
    let custom = Config::get_option("custom-rendezvous-server");
    let api_opt = Config::get_option("api-server");
    let base_api = crate::get_api_server(api_opt, custom);

    if base_api.is_empty() {
        return Err(anyhow!("No API server configured (option api-server empty)"));
    }

    let url = format!("{}/api/login", base_api.trim_end_matches('/'));

    let device_id = Config::get_id();
    let password = Config::get_option("device-password");
    let uuid = Config::get_option("device-uuid");

    let req = ApiAuthRequest {
        username: device_id.clone(),
        password,
        id: device_id,
        uuid,
    };

    let client = create_http_client_async();
    let resp = client.post(url).json(&req).send().await?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err(anyhow!("Device blocked by API: {}", resp.status()));
    }

    if !resp.status().is_success() {
        return Err(anyhow!("API login failed: {}", resp.status()));
    }

    let env: ApiLoginEnvelope = resp.json().await?;
    let login = env.login_response;

    let api_key = login.key;
    let rd_key = login.rustdesk_config.key;
    let host = login.rustdesk_config.host;
    let api_server = login.rustdesk_config.api_server;

    let final_key = if !rd_key.is_empty() { rd_key } else { api_key };
    if final_key.is_empty() {
        return Err(anyhow!("API login returned empty key"));
    }

    Config::set_option("key".to_string(), final_key);
    Config::set_option("api-token".to_string(), login.token);
    Config::set_option("api-permissions".to_string(), login.permissions);

    if !host.is_empty() {
        Config::set_option("custom-rendezvous-server".to_string(), host);
    }
    if !api_server.is_empty() {
        Config::set_option("api-server".to_string(), api_server);
    }

    log::info!("API login OK. Key/config applied from API.");
    Ok(())
}
