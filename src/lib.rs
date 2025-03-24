use anyhow::{anyhow, Error, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use testcontainers::core::ExecCommand;

use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};

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
    async fn get(&self, path: &str) -> Result<Response> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

        let url = format!("{}/{}", self.base_url, path);
        let resp = self.client.get(url).headers(headers).send().await?;
        Ok(resp)
    }

    /// Example method to call the `/whoami` endpoint which returns information
    /// about the current user and their Tailnets.
    pub async fn whoami(&self) -> anyhow::Result<WhoAmIResponse> {
        let resp = self.get("whoami").await?;
        if resp.status().is_success() {
            let data: WhoAmIResponse = resp.json().await?;
            Ok(data)
        } else {
            let error_body = resp.text().await?;
            Err(anyhow!("Tailscale whoami endpoint error: {}", error_body))
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
    ) -> Result<CreateAuthKeyResponse> {
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
            Err(anyhow!("Tailscale create_auth_key error: {}", error_body))
        }
    }

    /// Lists the devices in a tailnet.
    ///
    /// The `fields` parameter can be "all" to return all device fields, or "default" to only get
    /// limited fields (addresses, id, nodeId, user, name, hostname, etc). If `fields` is `None`,
    /// then no query parameter is applied, and the default fields set is returned.
    ///
    /// For details, see https://tailscale.com/kb/api#list-tailnet-devices.
    pub async fn list_devices(
        &self,
        tailnet: &str,
        fields: Option<&str>,
    ) -> Result<ListDevicesResponse> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

        // Build the URL, appending "?fields=___" if needed
        let mut url = format!("{}/tailnet/{}/devices", self.base_url, tailnet);
        if let Some(f) = fields {
            url.push_str(&format!("?fields={}", f));
        }

        let resp = self.client.get(url).headers(headers).send().await?;
        if resp.status().is_success() {
            let data: ListDevicesResponse = resp.json().await?;
            Ok(data)
        } else {
            let error_body = resp.text().await?;
            Err(anyhow!("Tailscale list_devices error: {}", error_body))
        }
    }

    /// Finds a single device by `name` in the specified `tailnet` using the `list_devices()` call.
    /// Returns `Ok(Some(device))` if found, `Ok(None)` if not found, or an error otherwise.
    ///
    /// You may pass `fields` as `Some("all")` to request all fields, or `None` (the default)
    /// to request the limited set. See `list_devices()` for more details.
    pub async fn find_device_by_name(
        &self,
        tailnet: &str,
        name: &str,
        fields: Option<&str>,
    ) -> Result<Option<TailnetDevice>> {
        let devices_response = self.list_devices(tailnet, fields).await?;

        // Debug: Print out the name we're trying to match:
        println!(
            "find_device_by_name: Searching for device matching '{}'",
            name
        );

        // Debug: Print out all devices' names, along with their first segment (split by '.')
        for d in &devices_response.devices {
            let raw_name = d.name.as_deref().unwrap_or("[no name]");
            let split_part = raw_name.split('.').next().unwrap_or("");
            println!(
                "  Device raw name: '{}', first_part='{}'",
                raw_name, split_part
            );
        }

        // Now actually do the find:
        let device = devices_response.devices.into_iter().find(|d| {
            let split_part = d
                .name
                .as_deref()
                .map(|nm| nm.split('.').next().unwrap_or(""));
            split_part == Some(name)
        });

        // Debug: Print if we found a device or not:
        match &device {
            Some(dev) => {
                println!(
                    "find_device_by_name: Matched device -> '{}'",
                    dev.name.as_deref().unwrap_or("")
                );
            }
            None => {
                println!("find_device_by_name: No device matched '{}'", name);
            }
        }

        Ok(device)
    }

    /// Deletes the specified device from the tailnet.
    /// The device must belong to the requesting user's tailnet. Deleting devices
    /// shared with the tailnet is not supported.
    ///
    /// # Arguments
    ///
    /// * `device_id` - The ID of the device to delete. This can be either the `nodeId`
    ///   or the numeric `id`.
    /// * `fields` - If provided, appends `?fields=default` or `?fields=all` to the
    ///   request. Defaults to the limited fields if omitted.
    ///
    /// # Returns
    ///
    /// * `Ok(TailnetDevice)` if the deletion is successful (Tailscale returns the deleted
    ///   device object in the response).
    /// * An error otherwise.
    pub async fn delete_device(
        &self,
        device_id: &str,
        fields: Option<&str>,
    ) -> Result<Option<TailnetDevice>> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

        // Build the URL, appending "?fields=___" if needed
        let mut url = format!("{}/device/{}", self.base_url, device_id);
        if let Some(f) = fields {
            url.push_str(&format!("?fields={}", f));
        }

        let resp = self.client.delete(url).headers(headers).send().await?;

        if resp.status().is_success() {
            // Since the Tailscale docs or actual API might hand us null, parse as Option
            let deleted_device: Option<TailnetDevice> = resp.json().await?;
            Ok(deleted_device)
        } else {
            let error_body = resp.text().await?;
            Err(anyhow!("Tailscale delete_device error: {}", error_body))
        }
    }

    /// Removes a device by its first name component if it exists on the specified tailnet.
    /// Returns an `Ok(Some(TailnetDevice))` containing the deleted device if it was found
    /// and removed, or `Ok(None)` if the device was not found. If Tailscale returns an error,
    /// an Err(...) is returned.
    ///
    /// # Arguments
    ///
    /// * `tailnet` - The name of the tailnet.
    /// * `name` - The device's first name component. For example, passing "my-dev"
    ///   will match device names like "my-dev.example.com".
    /// * `fields` - If provided, e.g. "all", returns more fields in the device object
    ///   from the Tailscale API. Defaults to limited fields if `None`.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(TailnetDevice))` if the device was found and successfully deleted.
    /// * `Ok(None)` if the device was not found.
    /// * An error otherwise.
    pub async fn remove_device_by_name(
        &self,
        tailnet: &str,
        name: &str,
        fields: Option<&str>,
    ) -> Result<Option<TailnetDevice>> {
        if let Some(device) = self.find_device_by_name(tailnet, name, fields).await? {
            // We can use either nodeId or id for deletion; prefer nodeId if present.
            if let Some(device_id) = device.nodeId.as_deref().or(device.id.as_deref()) {
                let deleted = self.delete_device(device_id, fields).await?;
                Ok(deleted)
            } else {
                Err(anyhow!("Device found, but it has no valid nodeId or id."))
            }
        } else {
            // Device not found
            Ok(None)
        }
    }

    /// Waits for a device to appear in the specified tailnet, matching by its first name component.
    /// Polls `find_device_by_name` up to `max_retries` times, sleeping `delay_secs` each time
    /// before giving up. Returns `Ok(Some(TailnetDevice))` if found, or `Ok(None)` if not found.
    pub async fn wait_for_device_by_name(
        &self,
        tailnet: &str,
        device_name: &str,
        fields: Option<&str>,
        max_retries: u32,
        delay_secs: u64,
    ) -> Result<Option<TailnetDevice>> {
        for attempt in 0..max_retries {
            match self
                .find_device_by_name(tailnet, device_name, fields)
                .await?
            {
                Some(device) => {
                    println!("Found device '{}' on attempt {}", device_name, attempt + 1);
                    return Ok(Some(device));
                }
                None => {
                    println!(
                        "Attempt {} - device '{}' not found yet, sleeping...",
                        attempt + 1,
                        device_name
                    );
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        }

        println!(
            "Reached maximum {} attempts, device '{}' not found.",
            max_retries, device_name
        );
        Ok(None)
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

/// Response from `GET /tailnet/{tailnet}/devices`
#[derive(Debug, Deserialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<TailnetDevice>,
}

/// Represents a single device entry from the tailnet devices list.
#[derive(Debug, Deserialize)]
pub struct TailnetDevice {
    pub addresses: Option<Vec<String>>,
    pub id: Option<String>,
    pub nodeId: Option<String>,
    pub user: Option<String>,
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub clientVersion: Option<String>,
    pub updateAvailable: Option<bool>,
    pub os: Option<String>,
    pub created: Option<String>,
    pub lastSeen: Option<String>,
    pub keyExpiryDisabled: Option<bool>,
    pub expires: Option<String>,
    pub authorized: Option<bool>,
    pub isExternal: Option<bool>,
    pub machineKey: Option<String>,
    pub nodeKey: Option<String>,
    pub blocksIncomingConnections: Option<bool>,
    pub enabledRoutes: Option<Vec<String>>,
    pub advertisedRoutes: Option<Vec<String>>,
    pub clientConnectivity: Option<ClientConnectivity>,
    pub tags: Option<Vec<String>>,
    pub tailnetLockError: Option<String>,
    pub tailnetLockKey: Option<String>,
    pub postureIdentity: Option<PostureIdentity>,
}

/// Nested client connectivity data.
#[derive(Debug, Deserialize)]
pub struct ClientConnectivity {
    pub endpoints: Option<Vec<String>>,
    pub latency: Option<std::collections::HashMap<String, LatencyInfo>>,
    pub mappingVariesByDestIP: Option<bool>,
    pub clientSupports: Option<ClientSupports>,
}

/// Per-exit-node latency info.
#[derive(Debug, Deserialize)]
pub struct LatencyInfo {
    pub preferred: Option<bool>,
    pub latencyMs: Option<f64>,
}

/// Flags indicating which network features the client supports.
#[derive(Debug, Deserialize)]
pub struct ClientSupports {
    pub hairPinning: Option<bool>,
    pub ipv6: Option<bool>,
    pub pcp: Option<bool>,
    pub pmp: Option<bool>,
    pub udp: Option<bool>,
    pub upnp: Option<bool>,
}

/// Helps encode any posture/identity info.
#[derive(Debug, Deserialize)]
pub struct PostureIdentity {
    pub serialNumbers: Option<Vec<String>>,
}

#[tokio::test]
async fn test_tailscale_normal_in_docker() -> Result<()> {
    // 1) Read your Tailscale API token + tailnet from env
    let token = std::env::var("TAILSCALE_API_KEY").expect("Please set TAILSCALE_API_KEY env var.");
    let tailnet = std::env::var("TAILSCALE_TAILNET").unwrap_or_else(|_| "-".to_string());

    let client = TailscaleClient::new(token);

    // 2) Create an auth key (optionally remove ephemeral & preauthorized)
    let request_body = CreateAuthKeyRequest {
        description: Some("Docker test device normal".to_string()),
        expirySeconds: None,
        capabilities: Capabilities {
            devices: Devices {
                create: Some(CreateOpts {
                    reusable: Some(true),
                    ephemeral: Some(true),
                    preauthorized: Some(true),
                    tags: Some(vec![]),
                }),
            },
        },
    };
    let response = client
        .create_auth_key(&tailnet, true, &request_body)
        .await?;

    let auth_key = response
        .key
        .as_ref()
        .expect("Expected 'key' in create_auth_key response");

    let test_device_name = format!("testcontainer-device-normal-{}", rand::random::<u16>());

    println!("Starting container with auth key: {}", auth_key);

    // Instead of calling tailscale up here, just pass environment variables:
    let container = GenericImage::new("my-tailscale", "latest")
        .with_env_var("TAILSCALE_AUTHKEY", auth_key)
        .with_env_var("TAILSCALE_HOSTNAME", test_device_name.clone())
        // If your entrypoint uses a socket path, this is optional
        // .with_cap_add("NET_ADMIN") // only if you're using a real tun device, not userspace
        .start()
        .await?;

    // At this point, Tailscale should already be up inside the container.
    // We may just check logs or run 'tailscale status' for verification:
    let mut status = container
        .exec(ExecCommand::new(vec![
            "/bin/sh",
            "-c",
            "tailscale status --json",
        ]))
        .await?;

    let stdout = status.stdout_to_vec().await?;
    println!(
        "tailscale status --json:\n{}",
        String::from_utf8_lossy(&stdout)
    );

    // 7) Wait for up to 30 attempts, sleeping 2s each
    let device_opt = client
        .wait_for_device_by_name(&tailnet, &test_device_name, None, 30, 2)
        .await?;

    // Ensure the device is actually found
    assert!(
        device_opt.is_some(),
        "Device {} did not appear in list_devices within the expected time",
        test_device_name
    );

    println!("Found device: {:?}", device_opt);

    // 8) Once found, we can delete
    client
        .remove_device_by_name(&tailnet, &test_device_name, None)
        .await?;

    println!("Deleted device");

    Ok(())
}
