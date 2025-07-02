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

### Running Tests

The library includes comprehensive **API contract tests** that verify the client correctly implements the Tailscale API contract using Docker containers as test devices.

#### Quick Start (3 steps)

1. **Set up environment**:
   Create a `.env` file in the project root and add the following variables:

   ```bash
   # Tailscale API credentials
   TAILSCALE_API_TOKEN=tskey-api-xxxxxxxxx
   TAILSCALE_TAILNET=your-org-name
   
   # Auth key for Docker containers  
   TS_AUTH_KEY=tskey-auth-xxxxxxxxx
   
   # Test configuration
   DEVICE_1=test-device-1
   DEVICE_2=test-device-2
   DEVICE_3=test-device-3
   EXPECTED_DOCKER_DEVICES=test-device-1,test-device-2,test-device-3
   TEST_TIMEOUT_SECONDS=120
   ```
   
   **Replace the placeholder values:**
   - `TAILSCALE_API_TOKEN`: Your Tailscale API token (starts with `tskey-api-`) - used by tests to call the Tailscale API
   - `TAILSCALE_TAILNET`: Your tailnet name (e.g., `your-org.com` or `-` for default)
   - `TS_AUTH_KEY`: Auth key for Docker containers (starts with `tskey-auth-`) - used by Docker containers to join your tailnet

2. **Start test environment**:
   ```bash
   docker-compose -f docker-compose.test.yml up -d
   ```

3. **Run tests**:
   ```bash
   cargo test --test api_contract
   ```

#### Prerequisites

- **Tailscale account** with API access enabled
- **API token** with device and auth key management permissions
- **Auth key** for Docker containers (create in Tailscale admin panel)
- **Docker** and **Docker Compose** installed

#### Environment Variables

The `.env` file serves as the single source of truth for test configuration:

```bash
# Tailscale API credentials
TAILSCALE_API_TOKEN=tskey-api-xxxxxxxxx
TAILSCALE_TAILNET=your-org-name

# Auth key for Docker containers  
TS_AUTH_KEY=tskey-auth-xxxxxxxxx

# Test configuration
DEVICE_1=test-device-1
DEVICE_2=test-device-2
DEVICE_3=test-device-3
EXPECTED_DOCKER_DEVICES=test-device-1,test-device-2,test-device-3
TEST_TIMEOUT_SECONDS=120
```

#### Test Environment

The Docker setup creates:
- **3 Tailscale test devices** that connect to your tailnet
- **Isolated test environment** with persistent state
- **Tight coupling** between Docker containers and test expectations

#### Test Types

The API contract tests include:

- **Docker Setup Verification**: Ensures all Docker containers are connected and authorized
- **Device Operations**: Tests device listing, searching, and waiting functionality
- **Auth Key Management**: Tests creating reusable and non-reusable auth keys
- **Error Handling**: Tests invalid tokens, tailnets, and edge cases
- **Comprehensive Workflow**: End-to-end test using multiple API calls

#### Customizing the Test Environment

To add or modify test devices:

1. **Update `.env`**:
   ```bash
   DEVICE_1=my-custom-device-1
   DEVICE_2=my-custom-device-2
   EXPECTED_DOCKER_DEVICES=my-custom-device-1,my-custom-device-2
   ```

2. **Update `docker-compose.test.yml`** to match the number of devices in your list

3. **Run tests** to verify the new setup

#### Cleanup

```bash
docker-compose -f docker-compose.test.yml down
```

#### Running Specific Tests

```bash
# Run all API contract tests
cargo test --test api_contract
```

## License

Licensed under the terms of the [Apache License 2.0](LICENSE).