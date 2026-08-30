//! Deterministic specification integrity and upstream drift tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const MANAGED_FILES: &[&str] = &[
    "lexicons/com/atproto/identity/resolveHandle.json",
    "lexicons/com/atproto/server/createSession.json",
    "lexicons/com/atproto/server/refreshSession.json",
    "schemas/rfc8414_authorization_server.json",
    "schemas/rfc9728_protected_resource.json",
    "schemas/rfc9449_dpop_proof.json",
    "schemas/atproto_client_metadata.json",
];

const UPSTREAM_FILES: &[&str] = &[
    "lexicons/com/atproto/identity/resolveHandle.json",
    "lexicons/com/atproto/server/createSession.json",
    "lexicons/com/atproto/server/refreshSession.json",
];

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let unique = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = repository
            .join("target/tmp-spec-tests")
            .join(format!("{name}-{}-{unique}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        for directory in ["lexicons", "schemas", "scripts"] {
            copy_tree(&repository.join(directory), &root.join(directory));
        }
        Self { root }
    }

    fn run(&self, argument: &str, environment: &[(&str, &Path)]) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(self.root.join("scripts/sync_specs.sh"))
            .arg(argument)
            .current_dir(&self.root);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn fixture(&self) -> PathBuf {
        let fixture = self.root.join("upstream-fixture");
        for path in UPSTREAM_FILES {
            let destination = fixture.join(path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(self.root.join(path), destination).unwrap();
        }
        fixture
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn local_verify_is_offline_and_passes_clean_copy() {
    let sandbox = Sandbox::new("offline-verify");
    let output = sandbox.run("--verify", &[]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("local specification integrity"));
}

#[test]
fn every_managed_artifact_tamper_is_rejected() {
    let sandbox = Sandbox::new("tamper");
    for path in MANAGED_FILES {
        let file = sandbox.root.join(path);
        let original = fs::read(&file).unwrap();
        let mut value: Value = serde_json::from_slice(&original).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("fixtureChange".to_string(), json!(true));
        fs::write(&file, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert_eq!(sandbox.run("--verify", &[]).status.code(), Some(1));
        fs::write(file, original).unwrap();
    }
}

#[test]
fn every_missing_artifact_is_rejected() {
    let sandbox = Sandbox::new("missing");
    for path in MANAGED_FILES {
        let file = sandbox.root.join(path);
        let original = fs::read(&file).unwrap();
        fs::remove_file(&file).unwrap();
        assert_eq!(sandbox.run("--verify", &[]).status.code(), Some(1));
        fs::write(file, original).unwrap();
    }
}

#[test]
fn missing_or_corrupt_manifest_is_not_regenerated_by_verify() {
    let sandbox = Sandbox::new("manifest");
    let manifest = sandbox.root.join("schemas/.checksums.sha256");
    fs::write(
        &manifest,
        format!("{}  {}\n", "0".repeat(64), MANAGED_FILES[0]),
    )
    .unwrap();
    assert_eq!(sandbox.run("--verify", &[]).status.code(), Some(1));
    fs::remove_file(&manifest).unwrap();
    assert_eq!(sandbox.run("--verify", &[]).status.code(), Some(1));
    assert!(!manifest.exists());
}

#[test]
fn controlled_upstream_fixture_detects_freshness_drift() {
    let sandbox = Sandbox::new("freshness");
    let fixture = sandbox.fixture();
    assert!(sandbox
        .run(
            "--check-upstream",
            &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)]
        )
        .status
        .success());

    let changed = fixture.join(UPSTREAM_FILES[0]);
    let mut value: Value = serde_json::from_slice(&fs::read(&changed).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("upstreamChange".to_string(), json!(true));
    fs::write(changed, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    assert_eq!(
        sandbox
            .run(
                "--check-upstream",
                &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)]
            )
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn failed_sync_preserves_all_managed_state_atomically() {
    let sandbox = Sandbox::new("atomic-sync");
    let fixture = sandbox.fixture();
    fs::write(fixture.join(UPSTREAM_FILES[1]), b"not json").unwrap();
    let watched = MANAGED_FILES
        .iter()
        .copied()
        .chain(["schemas/provenance.json", "schemas/.checksums.sha256"])
        .map(|path| (path, fs::read(sandbox.root.join(path)).unwrap()))
        .collect::<BTreeMap<_, _>>();

    assert!(!sandbox
        .run("--sync", &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)])
        .status
        .success());
    for (path, contents) in watched {
        assert_eq!(fs::read(sandbox.root.join(path)).unwrap(), contents);
    }
}

#[test]
fn manifest_generation_is_deterministic() {
    let sandbox = Sandbox::new("manifest-idempotence");
    assert!(sandbox.run("--generate-manifest", &[]).status.success());
    let first = fs::read(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    assert!(sandbox.run("--generate-manifest", &[]).status.success());
    let second = fs::read(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    assert_eq!(first, second);
}

#[test]
fn command_line_contract_has_distinct_error_status() {
    let sandbox = Sandbox::new("cli");
    assert!(sandbox.run("--help", &[]).status.success());
    assert_eq!(sandbox.run("--unknown", &[]).status.code(), Some(2));
}
