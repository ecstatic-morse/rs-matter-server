//! Integration tests for the Matter controller initialization.
//!
//! Verifies that we can create a new fabric, persist it to a temp directory,
//! and load it back on a second invocation.

use rs_matter_server::matter::controller::{init_matter, FabricConfig};

/// Test 1: Create a new fabric and verify it's installed.
#[test]
fn test_create_fabric() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    let config = FabricConfig::default();

    let matter = init_matter(&path, &config).expect("init_matter");

    // Verify a fabric is installed.
    assert!(matter.has_fabrics(), "expected a fabric to be installed");

    // Verify the fabric ID matches our config.
    let fabric_id = matter.with_state(|state| state.fabrics.iter().next().map(|f| f.fabric_id()));
    assert_eq!(fabric_id, Some(config.fabric_id));
}

/// The port a device will be told to come back to has to be the one this node
/// is listening on, so it is configured rather than assumed.
#[test]
fn the_configured_port_is_the_one_the_node_advertises() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    let config = FabricConfig {
        port: 5999,
        ..FabricConfig::default()
    };

    let matter = init_matter(&path, &config).expect("init_matter");
    assert_eq!(matter.port(), 5999);
    // The default is Matter's own port, not an ephemeral one.
    assert_eq!(FabricConfig::default().port, 5540);
}

/// Test 2: Reload an existing fabric from disk.
#[test]
fn test_reload_fabric() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    let config = FabricConfig::default();

    // First init: creates the fabric.
    {
        let matter = init_matter(&path, &config).expect("init_matter");
        assert!(matter.has_fabrics());
    }

    // Second init: should load from storage.
    let matter2 = init_matter(&path, &config).expect("reload");
    assert!(
        matter2.has_fabrics(),
        "fabric should be loaded from storage"
    );
}

/// Fabric creation must not be flaky.
///
/// CI hit `InvalidData` from `init_matter` once, on x86_64, where this suite
/// otherwise passes. Certificate and CSR encoding both embed DER-encoded
/// ECDSA signatures whose length varies with the random values inside them,
/// so a rare encoding case is the obvious suspect. Run with `--ignored` to
/// hunt for it.
#[test]
#[ignore]
fn fabric_creation_is_not_flaky() {
    // Roughly one creation in three hundred has failed, so a short run proves
    // nothing. Override with FABRIC_FLAKE_ITERATIONS when hunting.
    let iterations: usize = std::env::var("FABRIC_FLAKE_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);

    let mut failures = Vec::new();
    for attempt in 0..iterations {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().to_str().unwrap().to_string();
        if let Err(error) = init_matter(&path, &FabricConfig::default()) {
            failures.push(format!("attempt {attempt}: {error:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {iterations} fabric creations failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Group keys come back after a restart from their own file, and that file,
/// not the copy every `persist_fabric` also writes into the fabric blob,
/// decides: a key removed before the restart stays removed.
#[test]
fn group_keys_survive_a_restart_and_removals_stick() {
    use rs_matter_server::matter::controller::{init_controller, persist_fabric};
    use rs_matter_server::matter::interaction::{group_keys, remove_group_key, set_group_key};

    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    let config = FabricConfig::default();
    let index = |matter: &rs_matter::Matter<'_>| {
        matter
            .with_state(|state| state.fabrics.iter().next().map(|f| f.fab_idx()))
            .unwrap()
    };

    {
        let controller = init_controller(&path, &config).expect("init");
        let (matter, storage) = (&controller.matter, &controller.storage_path);
        let fabric = index(matter);
        set_group_key(matter, fabric, storage, 7, 1, &[0x11; 16]).unwrap();
        set_group_key(matter, fabric, storage, 8, 1, &[0x11; 16]).unwrap();
        set_group_key(matter, fabric, storage, 9, 2, &[0x22; 16]).unwrap();
        // The fabric blob now carries all three too.
        persist_fabric(matter, storage).unwrap();
        remove_group_key(matter, fabric, storage, 9).unwrap();

        // Setting what is there already doesn't touch the file.
        let file = storage.join("group-keys.json");
        let written = std::fs::metadata(&file).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        set_group_key(matter, fabric, storage, 7, 1, &[0x11; 16]).unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().modified().unwrap(),
            written
        );
    }

    let controller = init_controller(&path, &config).expect("reload");
    let keys = group_keys(&controller.matter, index(&controller.matter)).unwrap();
    assert_eq!(
        keys.groups.into_iter().collect::<Vec<_>>(),
        [(7, 1), (8, 1)]
    );
    assert_eq!(
        keys.key_sets.into_iter().collect::<Vec<_>>(),
        [(1, [0x11; 16])]
    );
}

/// A group key file that can't be read is set aside, not a reason not to
/// start.
#[test]
fn a_corrupt_group_key_file_does_not_stop_startup() {
    use rs_matter_server::matter::controller::init_controller;
    use rs_matter_server::matter::interaction::group_keys;

    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    drop(init_matter(&path, &FabricConfig::default()).expect("init"));
    std::fs::write(tmp.path().join("group-keys.json"), "{").unwrap();

    let controller = init_controller(&path, &FabricConfig::default()).expect("reload");
    let fabric = controller
        .matter
        .with_state(|state| state.fabrics.iter().next().map(|f| f.fab_idx()))
        .unwrap();
    assert!(group_keys(&controller.matter, fabric)
        .unwrap()
        .groups
        .is_empty());
    assert!(tmp.path().join("group-keys.json.corrupt").exists());
}

/// A key the fabric has no room for is refused, and leaves the keys already
/// there, in memory and on disk, as they were.
#[test]
fn a_group_key_past_the_fabric_limits_changes_nothing() {
    use rs_matter_server::matter::controller::init_controller;
    use rs_matter_server::matter::interaction::{group_keys, set_group_key};
    use rs_matter_server::storage::group_keys as stored;

    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().to_str().unwrap().to_string();
    let controller = init_controller(&path, &FabricConfig::default()).expect("init");
    let (matter, storage) = (&controller.matter, &controller.storage_path);
    let fabric = matter
        .with_state(|state| state.fabrics.iter().next().map(|f| f.fab_idx()))
        .unwrap();

    let mut group = 0;
    let refused = loop {
        group += 1;
        assert!(group < 64, "no limit reached");
        if let Err(error) = set_group_key(matter, fabric, storage, group, 1, &[0x11; 16]) {
            break error;
        }
    };
    assert!(refused.details.contains("group key"), "{}", refused.details);
    let kept = group_keys(matter, fabric).unwrap();
    assert_eq!(kept.groups.len(), group as usize - 1);
    assert_eq!(stored::load(storage).unwrap(), kept);
}
