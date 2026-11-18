//! The Matter group keys this controller encrypts group messages with.
//!
//! They live on the controller's own fabric in memory, where rs-matter reads
//! them, but are persisted here, in a file of their own, rather than through
//! the fabric blob: a build without rs-matter's `groups` feature must go on
//! loading the fabric exactly as it always has, and anything this file holds
//! is simply never read by it. The file is authoritative — at startup the
//! fabric's key sets and group map are replaced by what it says — so a copy
//! that ended up in the fabric blob (every `persist_fabric` writes the
//! in-memory groups too) can't bring back a key that was removed.
//!
//! ```json
//! {"version": 1,
//!  "key_sets": [{"key_set_id": 1, "epoch_key": "<base64, 16 bytes>"}],
//!  "groups": [{"group_id": 7, "key_set_id": 1}]}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The file, in the storage directory. Owner-only, like the issuer key.
pub const GROUP_KEYS_FILE: &str = "group-keys.json";

/// The one format there is; a file naming another is refused rather than
/// guessed at.
const VERSION: u32 = 1;

/// An epoch key is an AES-128 key.
pub const EPOCH_KEY_LEN: usize = 16;

pub type EpochKey = [u8; EPOCH_KEY_LEN];

/// Key sets by id, and the key set each group is encrypted with.
///
/// Two tables, as on the fabric, because a key set can serve several groups:
/// giving one of them a new key changes it for all of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupKeys {
    pub key_sets: BTreeMap<u16, EpochKey>,
    pub groups: BTreeMap<u16, u16>,
}

impl GroupKeys {
    /// Map `group_id` to key set `key_set_id` holding `epoch_key`.
    pub fn set(&mut self, group_id: u16, key_set_id: u16, epoch_key: EpochKey) {
        self.key_sets.insert(key_set_id, epoch_key);
        self.groups.insert(group_id, key_set_id);
    }

    /// Unmap `group_id`, and drop its key set once no group uses it.
    pub fn remove(&mut self, group_id: u16) {
        if let Some(key_set_id) = self.groups.remove(&group_id) {
            if !self.groups.values().any(|&id| id == key_set_id) {
                self.key_sets.remove(&key_set_id);
            }
        }
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        let file = File {
            version: VERSION,
            key_sets: self
                .key_sets
                .iter()
                .map(|(&key_set_id, key)| KeySetEntry {
                    key_set_id,
                    epoch_key: BASE64.encode(key),
                })
                .collect(),
            groups: self
                .groups
                .iter()
                .map(|(&group_id, &key_set_id)| GroupEntry {
                    group_id,
                    key_set_id,
                })
                .collect(),
        };
        Ok(serde_json::to_vec_pretty(&file)?)
    }

    fn from_json(bytes: &[u8]) -> Result<Self> {
        let file: File = serde_json::from_slice(bytes)?;
        if file.version != VERSION {
            bail!("unsupported version {}", file.version);
        }
        let mut keys = GroupKeys::default();
        for entry in file.key_sets {
            let key = BASE64
                .decode(&entry.epoch_key)
                .ok()
                .and_then(|key| EpochKey::try_from(key.as_slice()).ok())
                .with_context(|| {
                    format!("key set {}: epoch_key is not 16 bytes", entry.key_set_id)
                })?;
            if keys.key_sets.insert(entry.key_set_id, key).is_some() {
                bail!("key set {} appears twice", entry.key_set_id);
            }
        }
        for entry in file.groups {
            if !keys.key_sets.contains_key(&entry.key_set_id) {
                bail!(
                    "group {} uses key set {}, which is not in the file",
                    entry.group_id,
                    entry.key_set_id
                );
            }
            if keys
                .groups
                .insert(entry.group_id, entry.key_set_id)
                .is_some()
            {
                bail!("group {} appears twice", entry.group_id);
            }
        }
        Ok(keys)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    key_sets: Vec<KeySetEntry>,
    groups: Vec<GroupEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySetEntry {
    key_set_id: u16,
    epoch_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupEntry {
    group_id: u16,
    key_set_id: u16,
}

/// Read the group keys from `storage_path`. A missing file is no keys; one
/// that can't be read or parsed is an error, for the caller to decide about.
pub fn load(storage_path: &Path) -> Result<GroupKeys> {
    let path = storage_path.join(GROUP_KEYS_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GroupKeys::default())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    GroupKeys::from_json(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Write the group keys to `storage_path`, owner-only and atomically, so an
/// interrupted write leaves the previous keys in place.
pub fn save(storage_path: &Path, keys: &GroupKeys) -> Result<()> {
    let path = storage_path.join(GROUP_KEYS_FILE);
    super::private::write_private(&path, &keys.to_json()?)
        .with_context(|| format!("writing {}", path.display()))
}

/// Load the group keys for startup, where an unreadable file must not stop
/// the server: it is logged and moved aside (so the next `set_group_key`
/// doesn't overwrite the only copy of what it held), and the server starts
/// with no group keys, which a client can put back.
pub fn load_for_startup(storage_path: &Path) -> GroupKeys {
    match load(storage_path) {
        Ok(keys) => keys,
        Err(error) => {
            let path = storage_path.join(GROUP_KEYS_FILE);
            let aside = path.with_extension("json.corrupt");
            log::error!(
                "Starting without Matter group keys: {:#}; moving it to {}",
                error,
                aside.display()
            );
            if let Err(error) = std::fs::rename(&path, &aside) {
                log::warn!("Could not move {} aside: {}", path.display(), error);
            }
            GroupKeys::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> GroupKeys {
        let mut keys = GroupKeys::default();
        keys.set(7, 1, [0x11; 16]);
        keys.set(8, 1, [0x11; 16]);
        keys.set(9, 2, [0x22; 16]);
        keys
    }

    #[test]
    fn keys_survive_a_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &sample()).unwrap();
        assert_eq!(load(dir.path()).unwrap(), sample());

        let mode = std::fs::metadata(dir.path().join(GROUP_KEYS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_file_format_is_the_documented_one() {
        let json: serde_json::Value = serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "key_sets": [
                    {"key_set_id": 1, "epoch_key": BASE64.encode([0x11; 16])},
                    {"key_set_id": 2, "epoch_key": BASE64.encode([0x22; 16])},
                ],
                "groups": [
                    {"group_id": 7, "key_set_id": 1},
                    {"group_id": 8, "key_set_id": 1},
                    {"group_id": 9, "key_set_id": 2},
                ],
            })
        );
    }

    #[test]
    fn a_missing_file_is_no_keys() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), GroupKeys::default());
        assert_eq!(load_for_startup(dir.path()), GroupKeys::default());
    }

    #[test]
    fn a_key_set_goes_with_the_last_group_using_it() {
        let mut keys = sample();
        keys.remove(7);
        assert!(keys.key_sets.contains_key(&1), "group 8 still uses it");
        keys.remove(8);
        assert!(!keys.key_sets.contains_key(&1));
        keys.remove(8);
        keys.remove(1234);
        assert_eq!(keys.groups.keys().copied().collect::<Vec<_>>(), [9]);
    }

    #[test]
    fn a_corrupt_file_is_an_error_and_is_moved_aside_at_startup() {
        let bad: &[&str] = &[
            "not json",
            r#"{"version": 2, "key_sets": [], "groups": []}"#,
            r#"{"version": 1, "key_sets": [{"key_set_id": 1, "epoch_key": "AAAA"}], "groups": []}"#,
            r#"{"version": 1, "key_sets": [], "groups": [{"group_id": 1, "key_set_id": 1}]}"#,
        ];
        for contents in bad {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(GROUP_KEYS_FILE);
            std::fs::write(&path, contents).unwrap();
            assert!(load(dir.path()).is_err(), "{contents}");

            assert_eq!(load_for_startup(dir.path()), GroupKeys::default());
            assert!(!path.exists());
            assert_eq!(
                std::fs::read_to_string(dir.path().join("group-keys.json.corrupt")).unwrap(),
                *contents
            );
        }
    }
}
