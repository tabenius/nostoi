#![cfg(feature = "cli")]

use nostoi::{
    sealed::{self, Key, KeyStore},
    Draft,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

#[test]
fn ciphertext_is_authenticated_bound_to_subject_and_matches_libsodium_vector() {
    let key = Key::from_bytes([0x5a; 32]);
    let value = json!("attack at dawn");
    let sealed = sealed::seal_with_nonce(&value, "user:kid", &key, &[1; 24]).unwrap();
    assert_eq!(
        sealed["$sealed"]["ct"],
        "+eQsqM30uDIBKvvr343a0uxUgmBtAND1fDgjgNbIZ8U="
    );
    assert_eq!(sealed::open(&sealed, &key).unwrap(), value);
    assert!(sealed::open(&sealed, &Key::from_bytes([2; 32])).is_err());
    for (field, replacement) in [
        ("kid", json!("other")),
        ("v", json!(2)),
        ("alg", json!("other")),
        ("nonce", json!("AA==")),
        ("ct", json!("AA==")),
    ] {
        let mut changed = sealed.clone();
        changed["$sealed"][field] = replacement;
        assert!(sealed::open(&changed, &key).is_err());
    }
    let mut changed = sealed.clone();
    changed["$sealed"]["extra"] = json!(true);
    assert!(sealed::open(&changed, &key).is_err());
    assert!(sealed::seal(&json!(1.5), "subject", &key).is_err());
    assert!(sealed::seal(&value, "", &key).is_err());
    assert_ne!(
        sealed::seal(&value, "subject", &key).unwrap(),
        sealed::seal(&value, "subject", &key).unwrap()
    );
}

#[test]
fn store_erasure_preserves_chain_and_never_reuses_a_key_id() {
    let dir = tempfile::tempdir().unwrap();
    let chain = dir.path().join("audit.jsonl");
    let path = KeyStore::default_path(&chain);
    {
        let mut store = KeyStore::load(&path).unwrap();
        store.generate("opaque-subject-1").unwrap();
        let mut body = json!({"personal":"private@example.test","public":"visible"});
        sealed::seal_fields(
            &mut body,
            &[("personal".into(), "opaque-subject-1".into())],
            &store,
        )
        .unwrap();
        assert_eq!(sealed::render_body(&body, None)["personal"], "[sealed]");
        nostoi::append(
            &chain,
            Draft {
                actor: None,
                kind: "event",
                subject: None,
                body: body.clone(),
                at: None,
            },
        )
        .unwrap();
        let before = fs::read(&chain).unwrap();
        assert!(nostoi::verify(&chain, None).unwrap().ok);
        assert!(store.forget("opaque-subject-1").unwrap().is_some());
        assert!(store.key("opaque-subject-1").is_none());
        assert!(store.generate("opaque-subject-1").is_err());
        assert_eq!(
            sealed::render_body(&body, Some(&store))["personal"],
            "[erased]"
        );
        assert_eq!(fs::read(&chain).unwrap(), before);
        assert!(nostoi::verify(&chain, None).unwrap().ok);
    }
    let store = KeyStore::load(&path).unwrap();
    assert!(store.key("opaque-subject-1").is_none());
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("private@example.test"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn selection_is_atomic_and_missing_fields_or_keys_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = KeyStore::load(&dir.path().join("private/store.json")).unwrap();
    store.generate("subject").unwrap();
    let original = json!({"a":"private","b":2});
    for selections in [
        vec![
            ("a".into(), "subject".into()),
            ("absent".into(), "subject".into()),
        ],
        vec![("a".into(), "missing".into())],
        vec![
            ("a".into(), "subject".into()),
            ("a".into(), "subject".into()),
        ],
    ] {
        let mut value = original.clone();
        assert!(sealed::seal_fields(&mut value, &selections, &store).is_err());
        assert_eq!(value, original);
    }
}

#[test]
fn cooperating_writers_are_locked_and_display_does_not_wait_for_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private/store.json");
    let mut store = KeyStore::load(&path).unwrap();
    store.generate("subject").unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.parent().unwrap().join("store.lock"))
        .unwrap();
    assert!(lock.try_lock().is_err());
    let value = sealed::seal(&json!("private"), "subject", store.key("subject").unwrap()).unwrap();
    let record = json!({"body":{"personal":value}});
    assert_eq!(
        sealed::display_record(&record, &path).unwrap()["body"]["personal"],
        "[sealed]"
    );
    drop(store);
    lock.try_lock().unwrap();
    lock.unlock().unwrap();
}

#[cfg(unix)]
#[test]
fn insecure_stores_and_symlinks_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("store.json");
    fs::write(&path, "{\"v\":99,\"keys\":{}}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(KeyStore::load(&path).is_err());
    fs::write(&path, "{\"v\":1,\"keys\":{}}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(KeyStore::load(&path).is_err());
    fs::remove_file(&path).unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "original").unwrap();
    symlink(&target, &path).unwrap();
    assert!(KeyStore::load(&path).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "original");
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nostoi"))
        .args(args)
        .output()
        .unwrap()
}
fn succeeded(args: &[&str]) -> Output {
    let result = cli(args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

#[test]
fn cli_seals_forgets_audits_and_projects_without_modifying_original_records() {
    let dir = tempfile::tempdir().unwrap();
    let chain = dir.path().join("audit.jsonl");
    let chain = chain.to_str().unwrap();
    let input = dir.path().join("body.json");
    fs::write(
        &input,
        r#"{"personal":"private@example.test","public":"visible"}"#,
    )
    .unwrap();
    let body = format!("@{}", input.display());
    succeeded(&["keygen", "opaque-subject", "--chain", chain]);
    succeeded(&[
        "append",
        chain,
        "--kind",
        "event",
        "--body",
        &body,
        "--seal",
        "personal=opaque-subject",
    ]);
    let before = fs::read(chain).unwrap();
    assert!(!String::from_utf8_lossy(&before).contains("private@example.test"));
    let shown = succeeded(&["show", chain, "1", "--json"]);
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["record"]["body"]["personal"], "[sealed]");
    assert_eq!(shown["display_projection"], true);
    succeeded(&["forget", "opaque-subject", "--chain", chain]);
    let after = fs::read(chain).unwrap();
    assert!(after.starts_with(&before));
    assert!(nostoi::verify(Path::new(chain), None).unwrap().ok);
    let loaded = nostoi::open(Path::new(chain), None).unwrap();
    assert_eq!(loaded.entries[1].record["kind"], "key.erasure.requested");
    assert_eq!(loaded.entries[2].record["kind"], "key.erased");
    let shown = succeeded(&["show", chain, "1", "--json"]);
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["record"]["body"]["personal"], "[erased]");
    let raw = succeeded(&["show", chain, "1", "--json", "--raw"]);
    let raw: Value = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(raw["record"], loaded.entries[0].record);
    assert!(!cli(&["keygen", "opaque-subject", "--chain", chain])
        .status
        .success());
    assert!(!cli(&[
        "append",
        chain,
        "--kind",
        "event",
        "--body",
        &body,
        "--seal",
        "personal=opaque-subject"
    ])
    .status
    .success());
}

#[test]
fn broken_chain_does_not_destroy_keys() {
    let dir = tempfile::tempdir().unwrap();
    let chain = dir.path().join("audit.jsonl");
    let path = KeyStore::default_path(&chain);
    let chain = chain.to_str().unwrap();
    succeeded(&["keygen", "subject", "--chain", chain]);
    fs::write(chain, "not a chain\n").unwrap();
    assert!(!cli(&["forget", "subject", "--chain", chain])
        .status
        .success());
    assert!(KeyStore::load(&path).unwrap().key("subject").is_some());
}

#[test]
fn python_and_rust_sealed_fields_interoperate() {
    let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/python");
    let script = r#"
import json, nostoi
key=bytes([90])*32
value={"text":"går 🦆","items":[True,None,7]}
sealed=nostoi.seal(value,"opaque-subject",key,nonce=bytes([1])*24)
assert nostoi.open_sealed(sealed,key)==value
assert nostoi.render_body({"x":sealed})["x"]=="[sealed]"
assert nostoi.render_body({"x":sealed},erased_ids=["opaque-subject"])["x"]=="[erased]"
print(json.dumps(sealed))
"#;
    let result = Command::new("python3")
        .args(["-c", script])
        .env("PYTHONPATH", module)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Python interoperability needs PyNaCl for this test: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let plaintext = json!({"text":"går 🦆","items":[true,null,7]});
    let key = Key::from_bytes([90; 32]);
    assert_eq!(sealed::open(&value, &key).unwrap(), plaintext);
    assert_eq!(
        sealed::seal_with_nonce(&plaintext, "opaque-subject", &key, &[1; 24]).unwrap(),
        value
    );
}
