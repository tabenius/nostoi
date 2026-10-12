//! XChaCha20-Poly1305 fields. Chain digests cover ciphertext, never key material.
//! This retains the draft's v1 envelope and AAD; see docs/CRYPTO-SHREDDING.md.
use crate::{canonical, Error};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SEALED_KEY: &str = "$sealed";
pub const SEALED_ALG: &str = "xchacha20poly1305";
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);
impl Key {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; KEY_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|_| Error::Invalid("secure random source unavailable".into()))?;
        Ok(Self(bytes))
    }
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.0))
    }
}

fn invalid(reason: &str) -> Error {
    Error::Invalid(reason.into())
}
fn kid_valid(kid: &str) -> Result<(), Error> {
    if kid.is_empty() || kid.len() > 128 || kid.chars().any(char::is_control) {
        return Err(invalid(
            "key ID must be nonempty, at most 128 bytes, without control characters",
        ));
    }
    Ok(())
}
fn aad(kid: &str) -> Vec<u8> {
    format!("{SEALED_ALG}|{kid}|1").into_bytes()
}

pub fn sealed_kid(value: &Value) -> Option<&str> {
    value.get(SEALED_KEY)?.get("kid")?.as_str()
}
pub fn is_sealed(value: &Value) -> bool {
    value.get(SEALED_KEY).is_some()
}

pub fn seal(value: &Value, kid: &str, key: &Key) -> Result<Value, Error> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| invalid("secure random source unavailable"))?;
    seal_with_nonce(value, kid, key, &nonce)
}

/// Deterministic interoperability tests only: never reuse a nonce with a key.
pub fn seal_with_nonce(
    value: &Value,
    kid: &str,
    key: &Key,
    nonce: &[u8; NONCE_LEN],
) -> Result<Value, Error> {
    kid_valid(kid)?;
    canonical::check_native(value).map_err(Error::Invalid)?;
    let plaintext = Zeroizing::new(canonical::to_string(value));
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let n = XNonce::from(*nonce);
    let ct = cipher
        .encrypt(
            &n,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad(kid),
            },
        )
        .map_err(|_| invalid("sealing failed"))?;
    Ok(
        json!({"$sealed": {"v": 1, "alg": SEALED_ALG, "kid": kid, "nonce": STANDARD.encode(nonce), "ct": STANDARD.encode(ct)}}),
    )
}

pub fn open(value: &Value, key: &Key) -> Result<Value, Error> {
    let envelope = value
        .get(SEALED_KEY)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("invalid sealed envelope"))?;
    if value.as_object().map(|v| v.len()) != Some(1)
        || envelope.len() != 5
        || envelope.get("v").and_then(Value::as_u64) != Some(1)
        || envelope.get("alg").and_then(Value::as_str) != Some(SEALED_ALG)
    {
        return Err(invalid("unsupported or malformed sealed envelope"));
    }
    let kid = envelope
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing key ID"))?;
    kid_valid(kid)?;
    let decode = |name| -> Result<Vec<u8>, Error> {
        STANDARD
            .decode(
                envelope
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("missing ciphertext or nonce"))?,
            )
            .map_err(|_| invalid("invalid sealed base64"))
    };
    let nonce = decode("nonce")?;
    let ct = decode("ct")?;
    if nonce.len() != NONCE_LEN || ct.len() < 16 {
        return Err(invalid("invalid ciphertext or nonce length"));
    }
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| invalid("invalid nonce length"))?;
    let n = XNonce::from(nonce);
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(key.as_bytes().into())
            .decrypt(
                &n,
                Payload {
                    msg: &ct,
                    aad: &aad(kid),
                },
            )
            .map_err(|_| invalid("wrong key or tampered sealed field"))?,
    );
    let result: Value =
        serde_json::from_slice(&plaintext).map_err(|_| invalid("sealed plaintext is not JSON"))?;
    canonical::check_native(&result).map_err(Error::Invalid)?;
    Ok(result)
}

pub fn seal_fields(
    body: &mut Value,
    seals: &[(String, String)],
    store: &KeyStore,
) -> Result<(), Error> {
    let mut projected = body.clone();
    let object = projected
        .as_object_mut()
        .ok_or_else(|| invalid("body must be an object"))?;
    let mut seen = BTreeSet::new();
    for (field, kid) in seals {
        if !seen.insert(field) {
            return Err(invalid("duplicate sealed field selection"));
        }
        let value = object
            .get_mut(field)
            .ok_or_else(|| invalid("selected body field is missing"))?;
        if is_sealed(value) {
            return Err(invalid("selected body field is already sealed"));
        }
        let key = store.key(kid).ok_or_else(|| {
            invalid("subject key is missing or erased; create an explicit new key ID")
        })?;
        *value = seal(value, kid, key)?;
    }
    *body = projected;
    Ok(())
}

/// No store means unknown availability, not evidence of erasure.
pub fn render_body(value: &Value, store: Option<&KeyStore>) -> Value {
    render_value(value, store.map(|s| &s.erased))
}
fn render_value(value: &Value, erased: Option<&BTreeSet<String>>) -> Value {
    if is_sealed(value) {
        let erased =
            erased.is_some_and(|set| sealed_kid(value).is_some_and(|kid| set.contains(kid)));
        return json!(if erased { "[erased]" } else { "[sealed]" });
    }
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), render_value(v, erased)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| render_value(v, erased)).collect())
        }
        _ => value.clone(),
    }
}

/// A display projection, never suitable for re-verification. Reads an atomic
/// tombstone snapshot without taking the writer lock or decrypting any field.
pub fn display_record(record: &Value, path: &Path) -> Result<Value, Error> {
    check_private_file(path)?;
    let erased = match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = Zeroizing::new(text);
            let value: Value =
                serde_json::from_str(&text).map_err(|_| invalid("malformed key store"))?;
            if value.get("v").and_then(Value::as_u64) != Some(1) {
                return Err(invalid("unsupported key-store version"));
            }
            match value.get("erased") {
                None => BTreeSet::new(),
                Some(items) => items
                    .as_array()
                    .ok_or_else(|| invalid("invalid erasure tombstones"))?
                    .iter()
                    .map(|kid| {
                        kid.as_str()
                            .map(String::from)
                            .ok_or_else(|| invalid("invalid erased key ID"))
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(crate::error::io(path)(e)),
    };
    let mut result = record.clone();
    if let Some(body) = result.get_mut("body") {
        *body = render_value(body, Some(&erased));
    }
    Ok(result)
}

/// One private directory, advisory lock, durable atomic writes and erasure tombstones.
/// Locks protect cooperating processes only; the directory must be owner-private.
pub struct KeyStore {
    path: PathBuf,
    keys: BTreeMap<String, Key>,
    erased: BTreeSet<String>,
    _lock: File,
}
impl KeyStore {
    pub fn default_path(chain: &Path) -> PathBuf {
        let mut name = chain.as_os_str().to_owned();
        name.push(".keys");
        PathBuf::from(name).join("store.json")
    }
    pub fn load(path: &Path) -> Result<Self, Error> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| invalid("key store needs a private parent directory"))?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent).map_err(crate::error::io(parent))?;
        let metadata = std::fs::symlink_metadata(parent).map_err(crate::error::io(parent))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("key-store directory must not be a symlink"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(invalid(
                    "key-store directory must have owner-only permissions (0700)",
                ));
            }
        }
        let lock_path = parent.join("store.lock");
        check_private_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(&lock_path)
            .map_err(crate::error::io(&lock_path))?;
        lock.lock().map_err(crate::error::io(&lock_path))?;
        check_private_file(path)?;
        let mut store = Self {
            path: path.to_owned(),
            keys: BTreeMap::new(),
            erased: BTreeSet::new(),
            _lock: lock,
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => Zeroizing::new(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(e) => return Err(crate::error::io(path)(e)),
        };
        let value: Value =
            serde_json::from_str(&text).map_err(|_| invalid("malformed key store"))?;
        if value.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(invalid("unsupported key-store version"));
        }
        let keys = value
            .get("keys")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("key store lacks keys object"))?;
        for (kid, encoded) in keys {
            kid_valid(kid)?;
            let bytes = STANDARD
                .decode(
                    encoded
                        .as_str()
                        .ok_or_else(|| invalid("invalid encoded key"))?,
                )
                .map_err(|_| invalid("invalid encoded key"))?;
            let bytes: [u8; KEY_LEN] = bytes
                .try_into()
                .map_err(|_| invalid("key must be 32 bytes"))?;
            store.keys.insert(kid.clone(), Key::from_bytes(bytes));
        }
        if let Some(erased) = value.get("erased") {
            for kid in erased
                .as_array()
                .ok_or_else(|| invalid("invalid erasure tombstones"))?
            {
                let kid = kid
                    .as_str()
                    .ok_or_else(|| invalid("invalid erased key ID"))?;
                kid_valid(kid)?;
                if store.keys.contains_key(kid) {
                    return Err(invalid("erased key still present in store"));
                }
                store.erased.insert(kid.into());
            }
        }
        Ok(store)
    }
    pub fn key(&self, kid: &str) -> Option<&Key> {
        self.keys.get(kid)
    }
    pub fn generate(&mut self, kid: &str) -> Result<String, Error> {
        kid_valid(kid)?;
        if self.keys.contains_key(kid) || self.erased.contains(kid) {
            return Err(invalid("key ID already exists or was erased; use a new ID"));
        }
        let key = Key::generate()?;
        let fingerprint = key.fingerprint();
        self.keys.insert(kid.into(), key);
        if let Err(e) = self.save() {
            self.keys.remove(kid);
            return Err(e);
        }
        Ok(fingerprint)
    }
    /// Removes active key material; returns only its public fingerprint.
    pub fn forget(&mut self, kid: &str) -> Result<Option<String>, Error> {
        kid_valid(kid)?;
        let removed = self.keys.remove(kid);
        let existed = self.erased.contains(kid);
        self.erased.insert(kid.into());
        if let Err(e) = self.save() {
            if let Some(key) = removed {
                self.keys.insert(kid.into(), key);
            }
            if !existed {
                self.erased.remove(kid);
            }
            return Err(e);
        }
        Ok(removed.map(|key| key.fingerprint()))
    }
    fn save(&self) -> Result<(), Error> {
        let parent = self.path.parent().expect("validated parent");
        let keys: BTreeMap<_, _> = self
            .keys
            .iter()
            .map(|(kid, key)| (kid, STANDARD.encode(key.as_bytes())))
            .collect();
        let text = Zeroizing::new(canonical::to_string(
            &json!({"v":1,"keys":keys,"erased":self.erased}),
        ));
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(crate::error::io(parent))?;
        tmp.write_all(text.as_bytes())
            .map_err(crate::error::io(parent))?;
        tmp.as_file().sync_all().map_err(crate::error::io(parent))?;
        tmp.persist(&self.path)
            .map_err(|e| crate::error::io(&self.path)(e.error))?;
        #[cfg(unix)]
        {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(crate::error::io(parent))?;
        }
        Ok(())
    }
}

fn check_private_file(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid(
                    "key-store file must be a regular file, not a symlink",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(invalid(
                        "key-store files must have owner-only permissions (0600)",
                    ));
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::error::io(path)(e)),
    }
}
