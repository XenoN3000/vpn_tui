use crossterm::event::KeyCode;
use std::io::Write;
use tempfile::tempdir;
use vpn_tui::app::{ActiveModal, ActivePane, App, DeleteTarget};
use vpn_tui::domain::account::Account;
use vpn_tui::domain::config::{Profile, VpnProtocol};
use vpn_tui::domain::state::{ConnectionState, LatencyState};
use vpn_tui::ports::pinger::MockPinger;
use vpn_tui::ports::storage::{ConfigStorage, InMemoryStorage};
use vpn_tui::ports::vpn_runner::MockVpnRunner;

#[tokio::test]
async fn test_full_vpn_tui_lifecycle_e2e() {
    // 1. Setup in-memory environment with sample account and profiles
    let mut storage = InMemoryStorage::new();
    let account = Account::new("Primary Corp");
    storage.save_account(&account).unwrap();

    let oc_profile = Profile::new_openconnect("Munich DC", "vpn.munich.corp:443")
        .with_account(account.id.clone())
        .with_flag("--no-dtls");
    storage.save_profile(&oc_profile).unwrap();

    let ov_profile = Profile::new_openvpn("Frankfurt Lab", "vpn.fra.corp:1194", None)
        .with_account(account.id.clone());
    storage.save_profile(&ov_profile).unwrap();

    let pinger = MockPinger::new()
        .with_response("vpn.munich.corp:443", LatencyState::Measured(18))
        .with_response("vpn.fra.corp:1194", LatencyState::Measured(45));

    let runner = MockVpnRunner::new();

    let mut app = App::new(storage, runner, pinger);

    // 2. Verify loaded data
    assert_eq!(app.accounts.len(), 1);
    assert_eq!(app.profiles.len(), 2);
    assert_eq!(app.active_pane, ActivePane::Profiles);

    // 3. Ping all configurations
    app.handle_key(KeyCode::Char('p')).await.unwrap();
    let p0 = app.profiles.iter().find(|p| p.name == "Munich DC").unwrap();
    assert_eq!(p0.latency, LatencyState::Measured(18));
    let p1 = app
        .profiles
        .iter()
        .find(|p| p.name == "Frankfurt Lab")
        .unwrap();
    assert_eq!(p1.latency, LatencyState::Measured(45));

    // 4. Connect to Munich DC
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert!(app.connection_state.is_connected());
    assert!(
        app.logs
            .iter()
            .any(|l| l.contains("VPN Tunnel established"))
    );

    // 5. Disconnect
    app.handle_key(KeyCode::Char('d')).await.unwrap();
    assert_eq!(app.connection_state, ConnectionState::Disconnected);
    assert_eq!(app.active_profile_name, None);

    // 6. Open unified ConfigAdder modal and create OpenConnect configuration
    app.handle_key(KeyCode::Char('n')).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::ConfigAdder(_)));

    // Navigate to Profile Name (Field 2)
    app.handle_key(KeyCode::Tab).await.unwrap(); // Field 1: Account
    app.handle_key(KeyCode::Tab).await.unwrap(); // Field 2: Name
    for c in "Tokyo Edge".chars() {
        app.handle_key(KeyCode::Char(c)).await.unwrap();
    }
    // Navigate to Endpoint (Field 3)
    app.handle_key(KeyCode::Tab).await.unwrap();
    for c in "vpn.tokyo.corp:443".chars() {
        app.handle_key(KeyCode::Char(c)).await.unwrap();
    }
    // Save OpenConnect profile
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.profiles.len(), 3);
    assert!(app.profiles.iter().any(|p| p.name == "Tokyo Edge"));

    // 7. Test OpenVPN configuration creation with file browser flow
    let temp_dir = tempdir().unwrap();
    let ovpn_path = temp_dir.path().join("secure_access.ovpn");
    {
        let mut f = std::fs::File::create(&ovpn_path).unwrap();
        writeln!(f, "client\ndev tun\nremote 203.0.113.10 1194").unwrap();
    }

    // Open ConfigAdder
    app.handle_key(KeyCode::Char('n')).await.unwrap();
    // Toggle protocol to OpenVPN (Space on Field 0)
    app.handle_key(KeyCode::Char(' ')).await.unwrap();

    // Verify protocol is OpenVPN
    match &app.active_modal {
        ActiveModal::ConfigAdder(a) => assert_eq!(a.protocol, VpnProtocol::OpenVpn),
        other => panic!("Expected ConfigAdder, got {:?}", other),
    }

    // Open file browser via F2
    app.handle_key(KeyCode::F(2)).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::FileBrowser { .. }));

    // Set browser current_dir and refresh to find our temp file
    if let ActiveModal::FileBrowser { ref mut state, .. } = app.active_modal {
        state.current_dir = temp_dir.path().to_path_buf();
        state.refresh();
        let idx = state
            .entries
            .iter()
            .position(|e| e.name == "secure_access.ovpn")
            .expect("find file in browser");
        state.selected_index = idx;
    }

    // Press Enter to select file
    app.handle_key(KeyCode::Enter).await.unwrap();

    // Verify focus returned to ConfigAdder with path populated
    match &app.active_modal {
        ActiveModal::ConfigAdder(a) => {
            assert_eq!(a.ovpn_path, ovpn_path.to_string_lossy().to_string());
            assert_eq!(a.ovpn_name, "secure_access");
        }
        other => panic!("Expected ConfigAdder, got {:?}", other),
    }

    // Submit configuration
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.profiles.len(), 4);
    assert!(app.profiles.iter().any(|p| p.name == "secure_access"));

    // 8. Edit a configuration profile in-place
    // Find index of Tokyo Edge and select it
    let tokyo_idx = app
        .profiles
        .iter()
        .position(|p| p.name == "Tokyo Edge")
        .unwrap();
    app.select_profile_by_idx(tokyo_idx);
    app.handle_key(KeyCode::Char('e')).await.unwrap();

    let adder = match &app.active_modal {
        ActiveModal::ConfigAdder(a) => a.clone(),
        other => panic!("Expected ConfigAdder modal in edit mode, got {:?}", other),
    };
    assert!(adder.editing_profile_id.is_some());
    assert_eq!(adder.oc_name, "Tokyo Edge");

    // Clear and update endpoint
    let mut updated_adder = adder;
    updated_adder.oc_endpoint = "vpn.tokyo-updated.corp:443".into();
    app.submit_config_adder(updated_adder).await.unwrap();

    assert_eq!(app.profiles.len(), 4);
    let tokyo_prof = app
        .profiles
        .iter()
        .find(|p| p.name == "Tokyo Edge")
        .unwrap();
    assert_eq!(tokyo_prof.endpoint, "vpn.tokyo-updated.corp:443");

    // 9. Edit account in-place
    app.active_pane = ActivePane::Accounts;
    app.selected_account_idx = 0;
    app.handle_key(KeyCode::Char('e')).await.unwrap();

    let acc_modal = match &app.active_modal {
        ActiveModal::Account(a) => a.clone(),
        other => panic!("Expected Account modal in edit mode, got {:?}", other),
    };
    assert!(acc_modal.editing_account_id.is_some());
    assert_eq!(acc_modal.name, "Primary Corp");

    // Modify username to 'corpuser' and save
    app.handle_key(KeyCode::Tab).await.unwrap(); // Go to username field
    for c in "corpuser".chars() {
        app.handle_key(KeyCode::Char(c)).await.unwrap();
    }
    app.handle_key(KeyCode::Enter).await.unwrap();

    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(
        app.accounts[0]
            .credentials
            .as_ref()
            .unwrap()
            .username
            .as_deref(),
        Some("corpuser")
    );

    // 10. Delete configuration profile with confirmation
    app.active_pane = ActivePane::Profiles;
    let del_idx = app
        .profiles
        .iter()
        .position(|p| p.name == "Tokyo Edge")
        .unwrap();
    app.select_profile_by_idx(del_idx);

    // Trigger delete
    app.handle_key(KeyCode::Char('x')).await.unwrap();
    assert!(matches!(
        app.active_modal,
        ActiveModal::ConfirmDelete { .. }
    ));

    // Cancel with 'n'
    app.handle_key(KeyCode::Char('n')).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.profiles.len(), 4);

    // Trigger delete again and confirm with 'y'
    app.handle_key(KeyCode::Char('x')).await.unwrap();
    app.handle_key(KeyCode::Char('y')).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.profiles.len(), 3);
    assert!(!app.profiles.iter().any(|p| p.name == "Tokyo Edge"));

    // 11. Delete account with cascade unassignment
    app.active_pane = ActivePane::Accounts;
    app.selected_account_idx = 0;
    app.handle_key(KeyCode::Char('x')).await.unwrap();
    assert!(matches!(
        app.active_modal,
        ActiveModal::ConfirmDelete { .. }
    ));

    // Confirm delete with Enter
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.accounts.len(), 0);

    // Verify configurations are retained with account_id unassigned
    assert_eq!(app.profiles.len(), 3);
    for p in &app.profiles {
        assert_eq!(p.account_id, None);
    }
}

#[tokio::test]
async fn test_ssl_cert_probe_refusal_and_pinning_e2e() {
    use vpn_tui::domain::config::SslPolicy;
    use vpn_tui::ports::vpn_runner::CertProbeResult;

    let mut storage = InMemoryStorage::new();
    let account = Account::new("Corp Account");
    storage.save_account(&account).unwrap();

    let profile = Profile::new_openconnect("Amsterdam OC", "45.93.169.132:443")
        .with_account(account.id.clone());
    storage.save_profile(&profile).unwrap();

    let pinger = MockPinger::new();
    let warning = CertProbeResult::Warning {
        endpoint: "45.93.169.132:443".into(),
        subject: Some("CN=nl5.cdntak.com".into()),
        pin: "pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=".into(),
        reason: "certificate does not match hostname".into(),
    };
    let runner = MockVpnRunner::new().with_probe_result(warning);

    let mut app = App::new(storage, runner, pinger);

    // 1. Initial connect triggers CertWarning modal
    app.handle_key(KeyCode::Enter).await.unwrap();
    match &app.active_modal {
        ActiveModal::CertWarning(state) => {
            assert_eq!(state.endpoint, "45.93.169.132:443");
            assert_eq!(state.subject.as_deref(), Some("CN=nl5.cdntak.com"));
            assert_eq!(
                state.pin,
                "pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os="
            );
            assert_eq!(state.reason, "certificate does not match hostname");
        }
        other => panic!("Expected CertWarning modal, got {:?}", other),
    }
    assert_eq!(app.connection_state, ConnectionState::Disconnected);
    assert!(
        !app.runner
            .is_connected
            .load(std::sync::atomic::Ordering::SeqCst)
    );

    // 2. Refuse certificate with 'r'
    app.handle_key(KeyCode::Char('r')).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.connection_state, ConnectionState::Disconnected);
    assert!(
        !app.runner
            .is_connected
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(app.logs.iter().any(|l| l.contains("refused by user")));

    // Profile remains unchanged in storage
    let prof_storage = app
        .storage
        .load_profiles(None)
        .unwrap()
        .into_iter()
        .find(|p| p.name == "Amsterdam OC")
        .unwrap();
    assert!(
        !prof_storage
            .flags
            .iter()
            .any(|f| f.contains("--servercert"))
    );

    // 3. Connect again and Accept & Pin with 'a'
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::CertWarning(_)));

    app.handle_key(KeyCode::Char('a')).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);

    // Profile memory & storage should have pin
    let prof_memory = app
        .profiles
        .iter()
        .find(|p| p.name == "Amsterdam OC")
        .unwrap();
    assert!(prof_memory.flags.contains(
        &"--servercert=pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=".to_string()
    ));

    let prof_storage = app
        .storage
        .load_profiles(None)
        .unwrap()
        .into_iter()
        .find(|p| p.name == "Amsterdam OC")
        .unwrap();
    assert!(prof_storage.flags.contains(
        &"--servercert=pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=".to_string()
    ));

    // Connection is established
    assert!(app.connection_state.can_disconnect());
    assert!(
        app.runner
            .is_connected
            .load(std::sync::atomic::Ordering::SeqCst)
    );

    // 4. Strict SSL Policy abort test
    app.handle_key(KeyCode::Char('d')).await.unwrap(); // Disconnect
    assert_eq!(app.connection_state, ConnectionState::Disconnected);

    // Create a strict profile without pinned cert
    let strict_prof = Profile::new_openconnect("Strict Gateway", "45.93.169.132:443")
        .with_ssl_policy(SslPolicy::Strict);
    app.storage.save_profile(&strict_prof).unwrap();
    app.profiles = app.storage.load_profiles(None).unwrap();

    let strict_idx = app
        .profiles
        .iter()
        .position(|p| p.name == "Strict Gateway")
        .unwrap();
    app.select_profile_by_idx(strict_idx);

    app.handle_key(KeyCode::Enter).await.unwrap();
    // Modal should NOT be shown; connection aborted immediately
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(matches!(
        app.connection_state,
        ConnectionState::Failed { .. }
    ));
    assert!(app.logs.iter().any(|l| l.contains("Strict SSL policy")));
}

#[tokio::test]
async fn test_accounts_modal_overlay_and_dismiss() {
    let mut storage = InMemoryStorage::new();
    let account = Account::new("Primary Corp");
    storage.save_account(&account).unwrap();

    let prof = Profile::new_openconnect("Munich DC", "vpn.munich.corp:443");
    storage.save_profile(&prof).unwrap();

    let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
    assert_eq!(app.active_pane, ActivePane::Profiles);
    assert_eq!(app.active_modal, ActiveModal::None);

    // Pressing 'a' opens the accounts modal
    app.handle_key(KeyCode::Char('a')).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::Account(_)));

    // Pressing Esc closes the modal and restores focus to profiles list
    app.handle_key(KeyCode::Esc).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.active_pane, ActivePane::Profiles);
}

#[tokio::test]
async fn test_sync_modal_and_batch_import_e2e() {
    let mut storage = InMemoryStorage::new();
    let account = Account::new("BioVpnCorp");
    storage.save_account(&account).unwrap();

    let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

    // 1. Press 'S' to open Sync modal
    app.handle_key(KeyCode::Char('S')).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::SyncManager(_)));

    // 2. Select Method 2 (Batch Paste Server IPs)
    app.handle_key(KeyCode::Down).await.unwrap();
    app.handle_key(KeyCode::Down).await.unwrap();
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert!(matches!(app.active_modal, ActiveModal::BatchInput(_)));

    // 3. Type server text
    let server_entry = "Frankfurt 185.120.45.10:443";
    for c in server_entry.chars() {
        app.handle_key(KeyCode::Char(c)).await.unwrap();
    }

    // 4. Press Enter to import
    app.handle_key(KeyCode::Enter).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);

    // 5. Verify profile was imported and reloaded into profiles list
    assert_eq!(app.profiles.len(), 1);
    assert_eq!(app.profiles[0].name, "Frankfurt");
    assert_eq!(app.profiles[0].endpoint, "185.120.45.10:443");
    assert!(app.logs.iter().any(|l| l.contains("batch imported")));
}

#[tokio::test]
async fn test_accounts_manager_navigation_and_delete() {
    let mut storage = InMemoryStorage::new();
    let account = Account::new("Deletable Corp");
    storage.save_account(&account).unwrap();

    let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
    assert_eq!(app.accounts.len(), 1);

    // 1. Press 'A' to open Accounts Manager overlay
    app.handle_key(KeyCode::Char('A')).await.unwrap();
    assert_eq!(app.active_pane, ActivePane::Accounts);

    // 2. Press 'x' to trigger delete confirmation
    app.handle_key(KeyCode::Char('x')).await.unwrap();
    assert!(matches!(
        app.active_modal,
        ActiveModal::ConfirmDelete {
            target: DeleteTarget::Account { .. }
        }
    ));

    // 3. Confirm with 'y'
    app.handle_key(KeyCode::Char('y')).await.unwrap();
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.accounts.len(), 0);

    // 4. Press Esc to return to Profiles
    app.handle_key(KeyCode::Esc).await.unwrap();
    assert_eq!(app.active_pane, ActivePane::Profiles);
}
