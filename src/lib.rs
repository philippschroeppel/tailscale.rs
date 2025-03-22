use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::error::Error;

/// A client for interacting with Tailscale's v2 API.
pub struct TailscaleClient {
    pub base_url: String,
    pub token: String,
    client: Client,
}

impl TailscaleClient {
    /// Creates a new TailscaleClient with the given token, automatically
    /// setting the base URL to https://api.tailscale.com/api/v2
    pub fn new(token: String) -> Self {
        TailscaleClient {
            base_url: "https://api.tailscale.com/api/v2".to_string(),
            token,
            client: Client::new(),
        }
    }

    /// Constructs an authorized GET request for the given path.
    async fn get(&self, path: &str) -> Result<Response, Box<dyn Error>> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

        let url = format!("{}/{}", self.base_url, path);
        let resp = self.client.get(url).headers(headers).send().await?;
        Ok(resp)
    }

    /// Example method to call the `/whoami` endpoint which returns information
    /// about the current user and their Tailnets.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Box<dyn Error>> {
        let resp = self.get("whoami").await?;
        if resp.status().is_success() {
            let data: WhoAmIResponse = resp.json().await?;
            Ok(data)
        } else {
            let error_body = resp.text().await?;
            Err(format!("Tailscale whoami endpoint error: {}", error_body).into())
        }
    }

    /// Creates a new auth key in the specified tailnet, returning the newly generated key.
    /// The `all` parameter is optional in the API, but here we surface it directly
    /// to match the Tailscale docs example (e.g., `?all=true`).
    pub async fn create_auth_key(
        &self,
        tailnet: &str,
        all: bool,
        req_body: &CreateAuthKeyRequest,
    ) -> Result<CreateAuthKeyResponse, Box<dyn Error>> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));

        let url = format!("{}/tailnet/{}/keys?all={}", self.base_url, tailnet, all);

        let resp = self
            .client
            .post(url)
            .headers(headers)
            .json(req_body)
            .send()
            .await?;

        if resp.status().is_success() {
            let data = resp.json().await?;
            Ok(data)
        } else {
            let error_body = resp.text().await?;
            Err(format!("Tailscale create_auth_key error: {}", error_body).into())
        }
    }
}

/// Example response from `/whoami`
#[derive(Debug, Deserialize)]
pub struct WhoAmIResponse {
    pub logged_in: bool,
    #[serde(rename = "user")]
    pub user_info: Option<UserInfo>,
    #[serde(rename = "tailnet")]
    pub tailnet_info: Option<TailnetInfo>,
}

/// Minimal user info
#[derive(Debug, Deserialize)]
pub struct UserInfo {
    pub login_name: Option<String>,
    pub display_name: Option<String>,
    pub profile_pic_url: Option<String>,
}

/// Minimal tailnet info
#[derive(Debug, Deserialize)]
pub struct TailnetInfo {
    pub name: Option<String>,
    pub magic_dns: Option<bool>,
}

/// Request body for creating an auth key.
/// Adjust fields as needed based on Tailscale's docs.
#[derive(Debug, Serialize)]
pub struct CreateAuthKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expirySeconds: Option<u64>,

    pub capabilities: Capabilities,
}

/// The `capabilities` definition for Tailscale's auth key creation.
#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub devices: Devices,
}

/// Minimal required field under `devices`, though you can add sub-fields as needed.
#[derive(Debug, Serialize)]
pub struct Devices {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create: Option<CreateOpts>,
}

/// Example subfields that can be used when creating a device auth key.
#[derive(Debug, Serialize)]
pub struct CreateOpts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reusable: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preauthorized: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Response body from creating an auth key.
#[derive(Debug, Deserialize)]
pub struct CreateAuthKeyResponse {
    pub id: Option<String>,
    pub key: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub revoked: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<AuthKeyCapabilities>,

    pub description: Option<String>,
    pub invalid: Option<bool>,
    pub userId: Option<String>,
}

/// Nested capabilities info in the create-auth-key response.
#[derive(Debug, Deserialize)]
pub struct AuthKeyCapabilities {
    pub devices: Option<AuthKeyDevices>,
}

#[derive(Debug, Deserialize)]
pub struct AuthKeyDevices {
    pub create: Option<AuthKeyCreate>,
}

#[derive(Debug, Deserialize)]
pub struct AuthKeyCreate {
    pub reusable: Option<bool>,
    pub ephemeral: Option<bool>,
    pub preauthorized: Option<bool>,
    pub tags: Option<Vec<String>>,
}

/// Example synchronous `main` function
fn main() {
    println!(
        "Run the async example or tests to see the client in action. \
         This file defines a base Tailscale client with a create_auth_key method."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Integration test that performs a real create_auth_key call against Tailscale.
    /// To run this successfully, set the following environment variables:
    ///   - TAILSCALE_API_KEY: your Tailscale API key (e.g., tskey-api-XXXXX).
    ///   - TAILSCALE_TAILNET: the tailnet name (e.g., "example.com") or "-" for your default.
    ///
    /// Example usage:
    ///   TAILSCALE_API_KEY="tskey-api-XXXXX" \
    ///   TAILSCALE_TAILNET="myorg.com" \
    ///   cargo test -- --nocapture
    #[tokio::test]
    async fn test_create_auth_key_integration() -> Result<(), Box<dyn Error>> {
        let token = env::var("TAILSCALE_API_KEY")
            .expect("Please set env var TAILSCALE_API_KEY with a valid Tailscale API key");
        let tailnet = env::var("TAILSCALE_TAILNET").unwrap_or_else(|_| "-".to_string());

        // Build the Tailscale client
        let client = TailscaleClient::new(token);

        // Prepare the request body
        let request_body = CreateAuthKeyRequest {
            description: Some("Integration test auth key".to_string()),
            expirySeconds: None, // e.g. Some(86400) for 1 day
            capabilities: Capabilities {
                devices: Devices {
                    create: Some(CreateOpts {
                        reusable: Some(true),
                        ephemeral: Some(false),
                        preauthorized: Some(false),
                        tags: Some(vec!["tag:example".to_string()]),
                    }),
                },
            },
        };

        // Make the real call
        let response = client
            .create_auth_key(&tailnet, true, &request_body)
            .await?;

        println!("Create Auth Key response: {:#?}", response);

        // At a minimum, check that we got something back
        assert!(
            response.key.is_some(),
            "Expected some auth key in the `key` field"
        );

        Ok(())
    }
}
