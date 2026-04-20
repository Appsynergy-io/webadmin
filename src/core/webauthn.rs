/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::components::messages::alert::Alert;

use super::{
    http::{self, HttpRequest},
    oauth::{AuthenticationResponse, AuthenticationResult, OAuthGrant},
    Permissions,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct WebauthnAuthOptionsResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct WebauthnAuthOptionsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebauthnAuthVerifyRequest {
    pub challenge_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WebauthnRegisterOptionsResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct WebauthnRegisterVerifyRequest {
    pub challenge_id: String,
    pub name: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created: u64,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "stalwartWebauthn"], catch)]
    async fn register(options_json: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "stalwartWebauthn"], catch)]
    async fn authenticate(options_json: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "stalwartWebauthn"])]
    fn supported() -> bool;
}

pub fn is_webauthn_supported() -> bool {
    supported()
}

pub async fn webauthn_authenticate(
    base_url: &str,
    username: Option<&str>,
) -> AuthenticationResult<AuthenticationResponse> {
    // 1. Ask server for challenge
    let options: WebauthnAuthOptionsResponse = match HttpRequest::post(format!(
        "{base_url}/auth/webauthn/options"
    ))
    .with_body(WebauthnAuthOptionsRequest {
        username: username.map(|s| s.to_string()),
    })
    .unwrap()
    .send::<serde_json::Value>()
    .await
    {
        Ok(v) => match serde_json::from_value::<WebauthnAuthOptionsResponse>(v) {
            Ok(r) => r,
            Err(err) => {
                return AuthenticationResult::Error(
                    Alert::error("Invalid server response").with_details(err.to_string()),
                );
            }
        },
        Err(err) => return AuthenticationResult::Error(Alert::from(err)),
    };

    // 2. Prompt browser
    let options_json = serde_json::to_string(&options.options).unwrap_or_default();
    let assertion_js = match authenticate(&options_json).await {
        Ok(v) => v,
        Err(err) => {
            return AuthenticationResult::Error(
                Alert::warning("Passkey authentication was cancelled or failed")
                    .with_details(format!("{err:?}")),
            );
        }
    };

    let assertion_str = match assertion_js.as_string() {
        Some(s) => s,
        None => {
            return AuthenticationResult::Error(Alert::error("Browser returned no assertion"));
        }
    };
    let credential: serde_json::Value = match serde_json::from_str(&assertion_str) {
        Ok(v) => v,
        Err(err) => {
            return AuthenticationResult::Error(
                Alert::error("Invalid assertion from browser").with_details(err.to_string()),
            );
        }
    };

    // 3. Send assertion back for verification + token issuance
    #[derive(Deserialize)]
    struct VerifyResponse {
        data: OAuthGrant,
    }

    match HttpRequest::post(format!("{base_url}/auth/webauthn/verify"))
        .with_body(WebauthnAuthVerifyRequest {
            challenge_id: options.challenge_id,
            credential,
        })
        .unwrap()
        .send::<VerifyResponse>()
        .await
    {
        Ok(resp) => AuthenticationResult::Success(AuthenticationResponse {
            grant: resp.data,
            permissions: Default::default(),
            is_enterprise: false,
        }),
        Err(http::Error::Unauthorized) => AuthenticationResult::Error(
            Alert::warning("Passkey did not match any account"),
        ),
        Err(err) => AuthenticationResult::Error(Alert::from(err)),
    }
}

pub async fn webauthn_list(access_token: &str) -> Result<Vec<CredentialInfo>, http::Error> {
    #[derive(Deserialize)]
    struct ListResponse {
        data: Vec<CredentialInfo>,
    }
    HttpRequest::get("/api/account/webauthn")
        .with_header("Authorization", format!("Bearer {access_token}"))
        .send::<ListResponse>()
        .await
        .map(|r| r.data)
}

pub async fn webauthn_register_flow(
    access_token: &str,
    name: &str,
) -> Result<CredentialInfo, Alert> {
    let options: WebauthnRegisterOptionsResponse = match HttpRequest::post(
        "/api/account/webauthn/register/options",
    )
    .with_header("Authorization", format!("Bearer {access_token}"))
    .with_body(serde_json::json!({ "name": name }))
    .unwrap()
    .send::<serde_json::Value>()
    .await
    {
        Ok(v) => match v.get("data").cloned().and_then(|d| serde_json::from_value(d).ok()) {
            Some(r) => r,
            None => return Err(Alert::error("Invalid server response")),
        },
        Err(err) => return Err(Alert::from(err)),
    };

    let options_json = serde_json::to_string(&options.options).unwrap_or_default();
    let attestation_js = register(&options_json)
        .await
        .map_err(|err| Alert::warning("Passkey registration cancelled").with_details(format!("{err:?}")))?;

    let attestation_str = attestation_js
        .as_string()
        .ok_or_else(|| Alert::error("Browser returned no attestation"))?;
    let credential: serde_json::Value = serde_json::from_str(&attestation_str)
        .map_err(|err| Alert::error("Invalid attestation").with_details(err.to_string()))?;

    #[derive(Deserialize)]
    struct VerifyResponse {
        data: CredentialInfo,
    }

    HttpRequest::post("/api/account/webauthn/register/verify")
        .with_header("Authorization", format!("Bearer {access_token}"))
        .with_body(WebauthnRegisterVerifyRequest {
            challenge_id: options.challenge_id,
            name: name.to_string(),
            credential,
        })
        .unwrap()
        .send::<VerifyResponse>()
        .await
        .map(|r| r.data)
        .map_err(Alert::from)
}

pub async fn webauthn_delete(
    access_token: &str,
    credential_id: &str,
) -> Result<(), http::Error> {
    HttpRequest::delete(format!("/api/account/webauthn/{credential_id}"))
        .with_header("Authorization", format!("Bearer {access_token}"))
        .send::<serde_json::Value>()
        .await
        .map(|_| ())
}

#[allow(dead_code)]
fn _silence_unused(_: Permissions) {}
