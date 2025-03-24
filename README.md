# tailscale.rs

A modern, minimal Rust client for the Tailscale v2 API. This library provides simple methods to authenticate with Tailscale, retrieve user and Tailnet info, and create auth keys.

## Installation

Add this crate to your Cargo.toml:

```toml
[dependencies]
tailscale-client = "0.1.2"
```

## Usage

Below is a quick example that calls the whoami endpoint:

```rust
use tailscale_client::TailscaleClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Replace with your actual Tailscale API key.
    let client = TailscaleClient::new("tskey-api-XXXXXX".to_string());
    
    // Fetch info about the authenticated user and their Tailnets.
    let whoami_response = client.whoami().await?;
    println!("WhoAmI Response: {:?}", whoami_response);
    Ok(())
}
```

Create an auth key:

```rust
use std::error::Error;
use tailscale_client::{TailscaleClient, KeyCapabilities};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Your Tailscale API key
    let api_key = "tskey-api-XXXXXX".to_string();
    // Your Tailnet (e.g. "example.com", or "-" for the default)
    let tailnet = "example.com".to_string();

    // Create a new Tailscale client
    let client = TailscaleClient::new(api_key);

    // Configure capabilities for your new auth key
    let capabilities = KeyCapabilities {
        ephemeral: Some(true),       // If true, the key can only add ephemeral nodes
        reusable: Some(false),       // If true, allows repeated usage of this key
        preauthorized: Some(false),  // If true, devices added with this key are automatically approved
    };

    // Call create_auth_key to generate a new auth key with the specified capabilities
    let new_key = client.create_auth_key(&tailnet, capabilities).await?;

    println!("Successfully created auth key: {:?}", new_key);

    Ok(())
}
```

## Features

- Easy construction of a Tailscale API client.
- Simple helpers for common operations (e.g. /whoami).
- Create auth keys with flexible capabilities.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Developing

```sh
make build_test_image
make test
```

## License

Licensed under the terms of the [Apache License 2.0](LICENSE).