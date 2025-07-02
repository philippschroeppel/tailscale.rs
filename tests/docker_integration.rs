use tailscale_client::*;
use anyhow::Result;
use testcontainers::{GenericImage, core::ExecCommand, ImageExt, runners::AsyncRunner};
use dotenv::dotenv;

/// Test that creates a Tailscale container and verifies it connects properly
#[tokio::test]
async fn test_tailscale_normal_in_docker() -> Result<()> {
    dotenv().ok();
    // 1) Read your Tailscale API token + tailnet from env
    let token = std::env::var("TAILSCALE_API_TOKEN").expect("Please set TAILSCALE_API_TOKEN env var.");
    let tailnet = std::env::var("TAILSCALE_TAILNET").unwrap_or_else(|_| "-".to_string());

    let client = TailscaleClient::new(token);

    // 2) Create an auth key (optionally remove ephemeral & preauthorized)
    let request_body = CreateAuthKeyRequest {
        description: Some("Docker test device normal".to_string()),
        expiry_seconds: None,
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

    // Get the stdout as a Vec<u8>
    let stdout = status.stdout_to_vec().await?.to_vec();
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