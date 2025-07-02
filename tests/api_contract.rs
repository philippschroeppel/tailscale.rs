use tailscale_client::*;
use anyhow::Result;
use dotenv::dotenv;

/// Test configuration that's tightly coupled to the Docker setup
struct TestConfig {
    api_token: String,
    tailnet: String,
    expected_devices: Vec<String>,
    test_timeout_seconds: u64,
}

impl TestConfig {
    fn from_env() -> Self {
        dotenv().ok();
        
        let api_token = std::env::var("TAILSCALE_API_TOKEN")
            .expect("TAILSCALE_API_TOKEN environment variable must be set");
        let tailnet = std::env::var("TAILSCALE_TAILNET")
            .expect("TAILSCALE_TAILNET environment variable must be set");

        // Expected devices from docker-compose.test.yml
        let expected_devices = vec![
            "test-device-1".to_string(),
            "test-device-2".to_string(),
            "test-device-3".to_string(),
        ];

        // Test timeout - can be overridden via environment
        let test_timeout_seconds = std::env::var("TEST_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "120".to_string())
            .parse()
            .expect("TEST_TIMEOUT_SECONDS must be a valid number");

        TestConfig {
            api_token,
            tailnet,
            expected_devices,
            test_timeout_seconds,
        }
    }
}

// ============================================================================
// DOCKER SETUP VERIFICATION TESTS
// ============================================================================

/// Test that all Docker containers are properly connected to Tailscale
#[tokio::test]
async fn test_docker_devices_connected() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing Docker devices connection...");
    println!("Expected devices: {:?}", config.expected_devices);
    
    // Wait for all expected devices to appear
    for device_name in &config.expected_devices {
        println!("Waiting for device: {}", device_name);
        
        let device = client.wait_for_device_by_name(
            &config.tailnet, 
            device_name, 
            None, 
            (config.test_timeout_seconds / 5) as u32, // Divide timeout by number of devices
            5 // Check every 5 seconds
        ).await?;
        
        match device {
            Some(device) => {
                println!("✓ Device {} connected: {}", device_name, device.id.as_ref().unwrap());
                
                // Verify device is authorized
                if let Some(authorized) = device.authorized {
                    assert!(authorized, "Device {} should be authorized", device_name);
                }
                
                // Verify device has an IP address
                if let Some(addresses) = &device.addresses {
                    assert!(!addresses.is_empty(), "Device {} should have IP addresses", device_name);
                    println!("  IP addresses: {:?}", addresses);
                }
            }
            None => {
                return Err(anyhow::anyhow!("Device {} did not appear within timeout", device_name));
            }
        }
    }
    
    println!("✓ All Docker devices are connected!");
    Ok(())
}

/// Test that we can find all expected Docker devices by name
#[tokio::test]
async fn test_find_all_docker_devices() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing find_all_docker_devices...");
    
    for device_name in &config.expected_devices {
        let found_device = client.find_device_by_name(&config.tailnet, device_name, Some("all")).await?;
        assert!(found_device.is_some(), "Should find Docker device {}", device_name);
        
        let device = found_device.unwrap();
        println!("✓ Found device: {} (ID: {})", device_name, device.id.as_ref().unwrap());
        
        // Verify device has connectivity info
        if let Some(connectivity) = &device.clientConnectivity {
            if let Some(endpoints) = &connectivity.endpoints {
                assert!(!endpoints.is_empty(), "Device {} should have endpoints", device_name);
                println!("  Endpoints: {:?}", endpoints);
            }
        }
    }
    
    println!("✓ All Docker devices found!");
    Ok(())
}

/// Test that device count matches expected Docker containers
#[tokio::test]
async fn test_device_count_matches_docker() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing device count matches Docker setup...");
    
    let devices = client.list_devices(&config.tailnet, None).await?;
    println!("Found {} total devices in tailnet", devices.devices.len());
    
    // Count how many of our expected devices are present
    let mut found_count = 0;
    for device_name in &config.expected_devices {
        if let Some(_) = devices.devices.iter().find(|d| {
            d.name.as_deref()
                .map(|name| name.split('.').next().unwrap_or("") == device_name)
                .unwrap_or(false)
        }) {
            found_count += 1;
        }
    }
    
    assert_eq!(
        found_count, 
        config.expected_devices.len(), 
        "Should find all {} expected Docker devices, but found {}", 
        config.expected_devices.len(), 
        found_count
    );
    
    println!("✓ Device count matches Docker setup!");
    Ok(())
}

// ============================================================================
// API CONTRACT TESTS
// ============================================================================

/// Test listing devices with default fields
#[tokio::test]
async fn test_list_devices_default() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing list_devices with default fields...");
    
    let devices = client.list_devices(&config.tailnet, None).await?;
    println!("✓ Found {} devices in tailnet", devices.devices.len());
    
    // Verify we got some basic device info
    for device in &devices.devices {
        assert!(device.id.is_some() || device.nodeId.is_some(), "Device should have an ID");
    }
    
    println!("✓ List devices (default) test passed!");
    Ok(())
}

/// Test listing devices with all fields
#[tokio::test]
async fn test_list_devices_all_fields() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing list_devices with all fields...");
    
    let devices = client.list_devices(&config.tailnet, Some("all")).await?;
    println!("✓ Found {} devices with all fields", devices.devices.len());
    
    // Verify we got extended device info
    for device in &devices.devices {
        assert!(device.id.is_some() || device.nodeId.is_some(), "Device should have an ID");
        // With "all" fields, we should get more detailed info
        if let Some(connectivity) = &device.clientConnectivity {
            println!("  Device has connectivity info: {:?}", connectivity.endpoints);
        }
    }
    
    println!("✓ List devices (all fields) test passed!");
    Ok(())
}

/// Test finding a device by name
#[tokio::test]
async fn test_find_device_by_name() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing find_device_by_name...");
    
    // Test finding one of our Docker devices
    if let Some(first_device) = config.expected_devices.first() {
        let found_device = client.find_device_by_name(&config.tailnet, first_device, None).await?;
        assert!(found_device.is_some(), "Should find Docker device {}", first_device);
        println!("✓ Found device: {}", first_device);
    }
    
    // Test finding non-existent device
    let non_existent = client.find_device_by_name(&config.tailnet, "definitely-not-existent-device", None).await?;
    assert!(non_existent.is_none(), "Should not find non-existent device");
    
    println!("✓ Find device by name test passed!");
    Ok(())
}

/// Test finding a device by name with all fields
#[tokio::test]
async fn test_find_device_by_name_all_fields() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing find_device_by_name with all fields...");
    
    // Test finding one of our Docker devices
    if let Some(first_device) = config.expected_devices.first() {
        let found_device = client.find_device_by_name(&config.tailnet, first_device, Some("all")).await?;
        assert!(found_device.is_some(), "Should find Docker device {} with all fields", first_device);
        
        let device = found_device.unwrap();
        println!("✓ Found device: {} (ID: {})", first_device, device.id.as_ref().unwrap());
        
        // Verify we got extended info
        if let Some(connectivity) = &device.clientConnectivity {
            println!("  Device has connectivity info: {:?}", connectivity.endpoints);
        }
    }
    
    println!("✓ Find device by name (all fields) test passed!");
    Ok(())
}

// ============================================================================
// AUTH KEY TESTS
// ============================================================================

/// Test creating an auth key
#[tokio::test]
async fn test_create_auth_key() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing create_auth_key...");
    
    let create_request = CreateAuthKeyRequest {
        description: Some("API contract test auth key".to_string()),
        expirySeconds: Some(1800), // 30 minutes
        capabilities: Capabilities {
            devices: Devices {
                create: Some(CreateOpts {
                    reusable: Some(false),
                    ephemeral: Some(true),
                    preauthorized: Some(true),
                    tags: None,
                }),
            },
        },
    };
    
    let response = client.create_auth_key(&config.tailnet, false, &create_request).await?;
    
    assert!(response.key.is_some(), "Auth key should be created");
    assert!(response.id.is_some(), "Auth key should have an ID");
    
    println!("✓ Created auth key: {}", response.id.as_ref().unwrap());
    
    // Verify the auth key has the expected capabilities
    if let Some(capabilities) = response.capabilities {
        if let Some(devices) = capabilities.devices {
            if let Some(create) = devices.create {
                assert_eq!(create.reusable, Some(false));
                assert_eq!(create.ephemeral, Some(true));
                assert_eq!(create.preauthorized, Some(true));
                assert_eq!(create.tags, None);
            }
        }
    }
    
    println!("✓ Create auth key test passed!");
    Ok(())
}

/// Test creating a reusable auth key
#[tokio::test]
async fn test_create_reusable_auth_key() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing create_reusable_auth_key...");
    
    let create_request = CreateAuthKeyRequest {
        description: Some("Reusable API contract test auth key".to_string()),
        expirySeconds: Some(3600), // 1 hour
        capabilities: Capabilities {
            devices: Devices {
                create: Some(CreateOpts {
                    reusable: Some(true),
                    ephemeral: Some(false),
                    preauthorized: Some(false),
                    tags: None,
                }),
            },
        },
    };
    
    let response = client.create_auth_key(&config.tailnet, false, &create_request).await?;
    
    assert!(response.key.is_some(), "Reusable auth key should be created");
    assert!(response.id.is_some(), "Reusable auth key should have an ID");
    
    println!("✓ Created reusable auth key: {}", response.id.as_ref().unwrap());
    
    // Verify the auth key has the expected capabilities
    if let Some(capabilities) = response.capabilities {
        if let Some(devices) = capabilities.devices {
            if let Some(create) = devices.create {
                assert_eq!(create.reusable, Some(true));
                assert_eq!(create.ephemeral, Some(false));
                assert_eq!(create.preauthorized, Some(false));
                assert_eq!(create.tags, None);
            }
        }
    }
    
    println!("✓ Create reusable auth key test passed!");
    Ok(())
}

// ============================================================================
// DEVICE WAITING TESTS
// ============================================================================

/// Test waiting for a device that exists
#[tokio::test]
async fn test_wait_for_existing_device() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing wait_for_device_by_name with existing device...");
    
    // Test waiting for one of our Docker devices
    if let Some(first_device) = config.expected_devices.first() {
        let device = client.wait_for_device_by_name(&config.tailnet, first_device, None, 5, 1).await?;
        assert!(device.is_some(), "Should find existing Docker device when waiting: {}", first_device);
        println!("✓ Found existing device: {}", first_device);
    }
    
    println!("✓ Wait for existing device test passed!");
    Ok(())
}

/// Test waiting for a non-existent device (should timeout)
#[tokio::test]
async fn test_wait_for_nonexistent_device() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing wait_for_device_by_name with non-existent device...");
    
    let non_existent = client.wait_for_device_by_name(&config.tailnet, "non-existent-device-12345", None, 3, 1).await?;
    assert!(non_existent.is_none(), "Should not find non-existent device when waiting");
    
    println!("✓ Wait for non-existent device test passed!");
    Ok(())
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

/// Test error handling with invalid token
#[tokio::test]
async fn test_error_invalid_token() -> Result<()> {
    println!("Testing error handling with invalid token...");
    
    let invalid_client = TailscaleClient::new("invalid-token-12345".to_string());
    let result = invalid_client.whoami().await;
    assert!(result.is_err(), "Should fail with invalid token");
    
    println!("✓ Invalid token error handling test passed!");
    Ok(())
}

/// Test error handling with invalid tailnet
#[tokio::test]
async fn test_error_invalid_tailnet() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Testing error handling with invalid tailnet...");
    
    let result = client.list_devices("invalid-tailnet-name-12345", None).await;
    assert!(result.is_err(), "Should fail with invalid tailnet");
    
    println!("✓ Invalid tailnet error handling test passed!");
    Ok(())
}

// ============================================================================
// COMPREHENSIVE API WORKFLOW TEST
// ============================================================================

/// Test a comprehensive workflow using multiple API calls
#[tokio::test]
async fn test_comprehensive_api_workflow() -> Result<()> {
    let config = TestConfig::from_env();
    let client = TailscaleClient::new(config.api_token);
    
    println!("Running comprehensive API workflow test...");
    
    // Step 1: Verify Docker devices are available
    println!("✓ Step 1: Verifying Docker devices are available");
    for device_name in &config.expected_devices {
        let found = client.find_device_by_name(&config.tailnet, device_name, None).await?;
        assert!(found.is_some(), "Should find Docker device in workflow: {}", device_name);
    }
    
    // Step 2: List devices
    let devices = client.list_devices(&config.tailnet, None).await?;
    println!("✓ Step 2: Found {} devices in tailnet", devices.devices.len());
    
    // Step 3: Find a specific Docker device with all fields
    if let Some(first_device) = config.expected_devices.first() {
        let found = client.find_device_by_name(&config.tailnet, first_device, Some("all")).await?;
        assert!(found.is_some(), "Should find Docker device in workflow: {}", first_device);
        println!("✓ Step 3: Found device: {}", first_device);
    }
    
    // Step 4: Create an auth key
    let create_request = CreateAuthKeyRequest {
        description: Some("Workflow test auth key".to_string()),
        expirySeconds: Some(900), // 15 minutes
        capabilities: Capabilities {
            devices: Devices {
                create: Some(CreateOpts {
                    reusable: Some(false),
                    ephemeral: Some(true),
                    preauthorized: Some(true),
                    tags: None,
                }),
            },
        },
    };
    
    let auth_key = client.create_auth_key(&config.tailnet, false, &create_request).await?;
    assert!(auth_key.key.is_some());
    println!("✓ Step 4: Created auth key: {}", auth_key.id.as_ref().unwrap());
    
    // Step 5: Test device waiting
    if let Some(first_device) = config.expected_devices.first() {
        let found = client.wait_for_device_by_name(&config.tailnet, first_device, None, 5, 1).await?;
        assert!(found.is_some(), "Should find Docker device when waiting in workflow: {}", first_device);
        println!("✓ Step 5: Successfully waited for device: {}", first_device);
    }
    
    println!("✓ Comprehensive API workflow test completed successfully!");
    Ok(())
}
