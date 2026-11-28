//! Local `Configuration` state data schema and validation limits (`Stage 2.3`).
//!
//! No built-in game registry names or tag values live in source code: the server
//! receives [`ConfigurationData`] as a value (loaded at runtime from gitignored
//! `server-data/configuration-26.3.json`, or constructed with synthetic `ferrite:test_*`
//! identifiers in unit and integration tests).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PROTOCOL_VERSION;

/// Maximum allowed byte size of `configuration-26.3.json` (`2 MiB`).
pub const MAX_CONFIG_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Maximum UTF-8 / UTF-16 length of a resource location (`<namespace>:<path>`).
pub const MAX_IDENTIFIER_LEN: usize = 32_767;

/// Maximum length of a `KnownPackEntry` string field (`namespace`, `id`, `version`).
pub const MAX_KNOWN_PACK_FIELD_LEN: usize = 256;

/// Maximum number of feature flag identifiers in `Feature Flags` (`0x0d`).
pub const MAX_CONFIG_FEATURE_FLAGS: usize = 64;

/// Maximum number of entries in `Select Known Packs` (`0x0f` / `0x07`).
pub const MAX_CONFIG_KNOWN_PACKS: usize = 64;

/// Maximum number of synchronized dynamic registries (`Registry Data`, `0x07`).
pub const MAX_CONFIG_REGISTRIES: usize = 128;

/// Maximum number of entries within a single synchronized registry.
pub const MAX_CONFIG_ENTRIES_PER_REGISTRY: usize = 4_096;

/// Maximum total number of entries across all synchronized registries combined.
pub const MAX_CONFIG_TOTAL_REGISTRY_ENTRIES: usize = 16_384;

/// Maximum number of registries carried in `Update Tags` (`0x0e`).
pub const MAX_CONFIG_TAG_REGISTRIES: usize = 128;

/// Maximum number of tag groups within a single registry in `Update Tags`.
pub const MAX_CONFIG_TAGS_PER_REGISTRY: usize = 2_048;

/// Maximum number of numeric entry indices within a single tag group.
pub const MAX_CONFIG_INDICES_PER_TAG: usize = 8_192;

/// Maximum total number of numeric entry indices across all tags combined.
pub const MAX_CONFIG_TOTAL_TAG_INDICES: usize = 131_072;

/// Maximum numeric entry index permitted for static registries not listed in `registries`.
pub const MAX_CONFIG_STATIC_TAG_INDEX: i32 = 32_767;

/// Validation and deserialization errors for [`ConfigurationData`].
#[derive(Debug, Error)]
pub enum ConfigDataError {
    /// Raw JSON input exceeded [`MAX_CONFIG_JSON_BYTES`].
    #[error("configuration JSON size {len} exceeds maximum {max} bytes")]
    FileTooLarge { len: usize, max: usize },

    /// Malformed JSON syntax or unknown field.
    #[error("invalid configuration JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// JSON file targets a protocol version other than [`PROTOCOL_VERSION`].
    #[error("configuration protocol_version {found} does not match expected {expected}")]
    WrongProtocolVersion { found: i32, expected: i32 },

    /// Resource location did not conform to `<namespace>:<path>` rules.
    #[error("invalid resource location identifier: {0:?}")]
    InvalidIdentifier(String),

    /// Known pack field was empty or exceeded [`MAX_KNOWN_PACK_FIELD_LEN`].
    #[error(
        "invalid known_packs string field (empty or exceeds {MAX_KNOWN_PACK_FIELD_LEN} chars)"
    )]
    InvalidKnownPackField,

    /// Too many feature flags.
    #[error("feature_flags count {len} exceeds maximum {max}")]
    TooManyFeatureFlags { len: usize, max: usize },

    /// Too many known packs.
    #[error("known_packs count {len} exceeds maximum {max}")]
    TooManyKnownPacks { len: usize, max: usize },

    /// Too many registries in `registries`.
    #[error("registries count {len} exceeds maximum {max}")]
    TooManyRegistries { len: usize, max: usize },

    /// Too many entries in a single registry.
    #[error("registry entry count {len} exceeds maximum {max}")]
    TooManyEntriesInRegistry { len: usize, max: usize },

    /// Too many entries across all registries combined.
    #[error("total registry entries {len} exceeds maximum {max}")]
    TooManyTotalRegistryEntries { len: usize, max: usize },

    /// Duplicate registry identifier in `registries`.
    #[error("duplicate registry id {0:?}")]
    DuplicateRegistry(String),

    /// Duplicate entry identifier inside a registry.
    #[error("duplicate entry {entry:?} in registry {registry:?}")]
    DuplicateRegistryEntry { registry: String, entry: String },

    /// Too many registries in `tags`.
    #[error("tag registries count {len} exceeds maximum {max}")]
    TooManyTagRegistries { len: usize, max: usize },

    /// Too many tags in a single registry.
    #[error("tags count {len} in registry exceeds maximum {max}")]
    TooManyTagsInRegistry { len: usize, max: usize },

    /// Too many numeric indices in a single tag.
    #[error("tag indices count {len} exceeds maximum {max}")]
    TooManyIndicesInTag { len: usize, max: usize },

    /// Too many numeric indices across all tags combined.
    #[error("total tag indices {len} exceeds maximum {max}")]
    TooManyTotalTagIndices { len: usize, max: usize },

    /// Duplicate registry identifier in `tags`.
    #[error("duplicate tag registry id {0:?}")]
    DuplicateTagRegistry(String),

    /// Duplicate tag identifier inside a tag registry.
    #[error("duplicate tag {tag:?} in registry {registry:?}")]
    DuplicateTag { registry: String, tag: String },

    /// Negative VarInt index inside a tag.
    #[error("negative tag entry index {value}")]
    NegativeTagIndex { value: i32 },

    /// Tag index exceeded the entry count of a synchronized dynamic registry.
    #[error("tag index {index} out of bounds for dynamic registry of length {entry_count}")]
    DynamicTagIndexOutOfBounds { index: i32, entry_count: usize },

    /// Tag index exceeded [`MAX_CONFIG_STATIC_TAG_INDEX`] for a static registry.
    #[error("static registry tag index {index} exceeds maximum {max}")]
    StaticTagIndexOutOfBounds { index: i32, max: i32 },
}

/// Single entry in `Select Known Packs` (`namespace`, `id`, `version`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownPackEntry {
    pub namespace: String,
    pub id: String,
    pub version: String,
}

/// Synchronized dynamic registry entry order without embedded NBT (`has_data = false`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySkeleton {
    pub id: String,
    pub entries: Vec<String>,
}

/// Single tag group mapping a tag identifier to protocol entry indices (`26.3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagGroupEntry {
    pub id: String,
    pub entries: Vec<i32>,
}

/// Tags belonging to one dynamic or static registry in `Update Tags`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRegistryEntry {
    pub registry: String,
    pub tags: Vec<TagGroupEntry>,
}

/// Complete `Configuration`-phase dataset injected into the server as a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationData {
    pub protocol_version: i32,
    pub feature_flags: Vec<String>,
    pub known_packs: Vec<KnownPackEntry>,
    pub registries: Vec<RegistrySkeleton>,
    pub tags: Vec<TagRegistryEntry>,
}

/// Validates a resource location string (`<namespace>:<path>`).
#[must_use]
pub fn is_valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LEN {
        return false;
    }
    let Some((namespace, path)) = value.split_once(':') else {
        return false;
    };
    if namespace.is_empty() || path.is_empty() {
        return false;
    }
    let ns_ok = namespace
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    let path_ok = path
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'/'));
    ns_ok && path_ok
}

fn is_valid_known_pack_field(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_KNOWN_PACK_FIELD_LEN
        && !value.chars().any(char::is_control)
}

impl ConfigurationData {
    /// Parses and validates [`ConfigurationData`] from raw JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ConfigDataError> {
        if bytes.len() > MAX_CONFIG_JSON_BYTES {
            return Err(ConfigDataError::FileTooLarge {
                len: bytes.len(),
                max: MAX_CONFIG_JSON_BYTES,
            });
        }
        let data: Self = serde_json::from_slice(bytes)?;
        data.validate()?;
        Ok(data)
    }

    /// Validates all structural invariants, bounds, and resource locations.
    pub fn validate(&self) -> Result<(), ConfigDataError> {
        use std::collections::{HashMap, HashSet};

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ConfigDataError::WrongProtocolVersion {
                found: self.protocol_version,
                expected: PROTOCOL_VERSION,
            });
        }

        if self.feature_flags.len() > MAX_CONFIG_FEATURE_FLAGS {
            return Err(ConfigDataError::TooManyFeatureFlags {
                len: self.feature_flags.len(),
                max: MAX_CONFIG_FEATURE_FLAGS,
            });
        }
        for flag in &self.feature_flags {
            if !is_valid_identifier(flag) {
                return Err(ConfigDataError::InvalidIdentifier(flag.clone()));
            }
        }

        if self.known_packs.len() > MAX_CONFIG_KNOWN_PACKS {
            return Err(ConfigDataError::TooManyKnownPacks {
                len: self.known_packs.len(),
                max: MAX_CONFIG_KNOWN_PACKS,
            });
        }
        for pack in &self.known_packs {
            if !is_valid_known_pack_field(&pack.namespace)
                || !is_valid_known_pack_field(&pack.id)
                || !is_valid_known_pack_field(&pack.version)
            {
                return Err(ConfigDataError::InvalidKnownPackField);
            }
        }

        if self.registries.len() > MAX_CONFIG_REGISTRIES {
            return Err(ConfigDataError::TooManyRegistries {
                len: self.registries.len(),
                max: MAX_CONFIG_REGISTRIES,
            });
        }

        let mut dynamic_registry_sizes: HashMap<&str, usize> =
            HashMap::with_capacity(self.registries.len());
        let mut total_registry_entries: usize = 0;

        for reg in &self.registries {
            if !is_valid_identifier(&reg.id) {
                return Err(ConfigDataError::InvalidIdentifier(reg.id.clone()));
            }
            if reg.entries.len() > MAX_CONFIG_ENTRIES_PER_REGISTRY {
                return Err(ConfigDataError::TooManyEntriesInRegistry {
                    len: reg.entries.len(),
                    max: MAX_CONFIG_ENTRIES_PER_REGISTRY,
                });
            }
            total_registry_entries = total_registry_entries.saturating_add(reg.entries.len());
            if total_registry_entries > MAX_CONFIG_TOTAL_REGISTRY_ENTRIES {
                return Err(ConfigDataError::TooManyTotalRegistryEntries {
                    len: total_registry_entries,
                    max: MAX_CONFIG_TOTAL_REGISTRY_ENTRIES,
                });
            }
            if dynamic_registry_sizes
                .insert(reg.id.as_str(), reg.entries.len())
                .is_some()
            {
                return Err(ConfigDataError::DuplicateRegistry(reg.id.clone()));
            }

            let mut seen_entries: HashSet<&str> = HashSet::with_capacity(reg.entries.len());
            for entry in &reg.entries {
                if !is_valid_identifier(entry) {
                    return Err(ConfigDataError::InvalidIdentifier(entry.clone()));
                }
                if !seen_entries.insert(entry.as_str()) {
                    return Err(ConfigDataError::DuplicateRegistryEntry {
                        registry: reg.id.clone(),
                        entry: entry.clone(),
                    });
                }
            }
        }

        if self.tags.len() > MAX_CONFIG_TAG_REGISTRIES {
            return Err(ConfigDataError::TooManyTagRegistries {
                len: self.tags.len(),
                max: MAX_CONFIG_TAG_REGISTRIES,
            });
        }

        let mut seen_tag_registries: HashSet<&str> = HashSet::with_capacity(self.tags.len());
        let mut total_tag_indices: usize = 0;

        for tag_reg in &self.tags {
            if !is_valid_identifier(&tag_reg.registry) {
                return Err(ConfigDataError::InvalidIdentifier(tag_reg.registry.clone()));
            }
            if !seen_tag_registries.insert(tag_reg.registry.as_str()) {
                return Err(ConfigDataError::DuplicateTagRegistry(
                    tag_reg.registry.clone(),
                ));
            }
            if tag_reg.tags.len() > MAX_CONFIG_TAGS_PER_REGISTRY {
                return Err(ConfigDataError::TooManyTagsInRegistry {
                    len: tag_reg.tags.len(),
                    max: MAX_CONFIG_TAGS_PER_REGISTRY,
                });
            }

            let dynamic_entry_count = dynamic_registry_sizes
                .get(tag_reg.registry.as_str())
                .copied();
            let mut seen_tags: HashSet<&str> = HashSet::with_capacity(tag_reg.tags.len());

            for group in &tag_reg.tags {
                if !is_valid_identifier(&group.id) {
                    return Err(ConfigDataError::InvalidIdentifier(group.id.clone()));
                }
                if !seen_tags.insert(group.id.as_str()) {
                    return Err(ConfigDataError::DuplicateTag {
                        registry: tag_reg.registry.clone(),
                        tag: group.id.clone(),
                    });
                }
                if group.entries.len() > MAX_CONFIG_INDICES_PER_TAG {
                    return Err(ConfigDataError::TooManyIndicesInTag {
                        len: group.entries.len(),
                        max: MAX_CONFIG_INDICES_PER_TAG,
                    });
                }
                total_tag_indices = total_tag_indices.saturating_add(group.entries.len());
                if total_tag_indices > MAX_CONFIG_TOTAL_TAG_INDICES {
                    return Err(ConfigDataError::TooManyTotalTagIndices {
                        len: total_tag_indices,
                        max: MAX_CONFIG_TOTAL_TAG_INDICES,
                    });
                }

                for &idx in &group.entries {
                    if idx < 0 {
                        return Err(ConfigDataError::NegativeTagIndex { value: idx });
                    }
                    if let Some(entry_count) = dynamic_entry_count {
                        if (idx as usize) >= entry_count {
                            return Err(ConfigDataError::DynamicTagIndexOutOfBounds {
                                index: idx,
                                entry_count,
                            });
                        }
                    } else if idx > MAX_CONFIG_STATIC_TAG_INDEX {
                        return Err(ConfigDataError::StaticTagIndexOutOfBounds {
                            index: idx,
                            max: MAX_CONFIG_STATIC_TAG_INDEX,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates and serializes [`ConfigurationData`] as pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, ConfigDataError> {
        self.validate()?;
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_synthetic_config() -> ConfigurationData {
        ConfigurationData {
            protocol_version: PROTOCOL_VERSION,
            feature_flags: vec!["ferrite:test_flag".to_owned()],
            known_packs: vec![KnownPackEntry {
                namespace: "ferrite".to_owned(),
                id: "test_pack".to_owned(),
                version: "26.3".to_owned(),
            }],
            registries: vec![RegistrySkeleton {
                id: "ferrite:test_registry".to_owned(),
                entries: vec![
                    "ferrite:test_entry_0".to_owned(),
                    "ferrite:test_entry_1".to_owned(),
                ],
            }],
            tags: vec![
                TagRegistryEntry {
                    registry: "ferrite:test_registry".to_owned(),
                    tags: vec![TagGroupEntry {
                        id: "ferrite:test_tag".to_owned(),
                        entries: vec![0, 1],
                    }],
                },
                TagRegistryEntry {
                    registry: "ferrite:test_static_registry".to_owned(),
                    tags: vec![TagGroupEntry {
                        id: "ferrite:test_static_tag".to_owned(),
                        entries: vec![0, 42],
                    }],
                },
            ],
        }
    }

    #[test]
    fn synthetic_config_json_roundtrip() {
        let cfg = sample_synthetic_config();
        let json = cfg.to_json_pretty().unwrap();
        let decoded = ConfigurationData::from_json_bytes(json.as_bytes()).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn rejects_oversized_json_bytes() {
        let oversized = vec![b' '; MAX_CONFIG_JSON_BYTES + 1];
        assert!(matches!(
            ConfigurationData::from_json_bytes(&oversized),
            Err(ConfigDataError::FileTooLarge {
                len,
                max: MAX_CONFIG_JSON_BYTES
            }) if len == MAX_CONFIG_JSON_BYTES + 1
        ));
    }

    #[test]
    fn rejects_wrong_protocol_and_invalid_identifiers() {
        let mut wrong_proto = sample_synthetic_config();
        wrong_proto.protocol_version = 776;
        assert!(matches!(
            wrong_proto.validate(),
            Err(ConfigDataError::WrongProtocolVersion {
                found: 776,
                expected: PROTOCOL_VERSION
            })
        ));

        for bad_id in [
            "",
            "no_colon",
            ":empty_ns",
            "ferrite:",
            "Upper:case",
            "ferrite:bad space",
        ] {
            let mut bad = sample_synthetic_config();
            bad.feature_flags = vec![bad_id.to_owned()];
            assert!(
                matches!(bad.validate(), Err(ConfigDataError::InvalidIdentifier(_))),
                "expected InvalidIdentifier for {bad_id:?}"
            );
        }
    }

    #[test]
    fn rejects_exceeding_collection_limits() {
        let mut too_many_regs = sample_synthetic_config();
        too_many_regs.registries = (0..=MAX_CONFIG_REGISTRIES)
            .map(|i| RegistrySkeleton {
                id: format!("ferrite:reg_{i}"),
                entries: Vec::new(),
            })
            .collect();
        assert!(matches!(
            too_many_regs.validate(),
            Err(ConfigDataError::TooManyRegistries { .. })
        ));

        let mut too_many_entries = sample_synthetic_config();
        too_many_entries.registries = vec![RegistrySkeleton {
            id: "ferrite:reg".to_owned(),
            entries: (0..=MAX_CONFIG_ENTRIES_PER_REGISTRY)
                .map(|i| format!("ferrite:entry_{i}"))
                .collect(),
        }];
        assert!(matches!(
            too_many_entries.validate(),
            Err(ConfigDataError::TooManyEntriesInRegistry { .. })
        ));

        let mut too_many_tags = sample_synthetic_config();
        too_many_tags.tags = vec![TagRegistryEntry {
            registry: "ferrite:test_static_registry".to_owned(),
            tags: (0..=MAX_CONFIG_TAGS_PER_REGISTRY)
                .map(|i| TagGroupEntry {
                    id: format!("ferrite:tag_{i}"),
                    entries: Vec::new(),
                })
                .collect(),
        }];
        assert!(matches!(
            too_many_tags.validate(),
            Err(ConfigDataError::TooManyTagsInRegistry { .. })
        ));

        let mut too_many_indices = sample_synthetic_config();
        too_many_indices.tags = vec![TagRegistryEntry {
            registry: "ferrite:test_static_registry".to_owned(),
            tags: vec![TagGroupEntry {
                id: "ferrite:big_tag".to_owned(),
                entries: vec![0; MAX_CONFIG_INDICES_PER_TAG + 1],
            }],
        }];
        assert!(matches!(
            too_many_indices.validate(),
            Err(ConfigDataError::TooManyIndicesInTag { .. })
        ));

        let mut too_many_flags = sample_synthetic_config();
        too_many_flags.feature_flags = (0..=MAX_CONFIG_FEATURE_FLAGS)
            .map(|i| format!("ferrite:flag_{i}"))
            .collect();
        assert!(matches!(
            too_many_flags.validate(),
            Err(ConfigDataError::TooManyFeatureFlags { .. })
        ));

        let mut too_many_packs = sample_synthetic_config();
        too_many_packs.known_packs = (0..=MAX_CONFIG_KNOWN_PACKS)
            .map(|i| KnownPackEntry {
                namespace: "ferrite".to_owned(),
                id: format!("pack_{i}"),
                version: "26.3".to_owned(),
            })
            .collect();
        assert!(matches!(
            too_many_packs.validate(),
            Err(ConfigDataError::TooManyKnownPacks { .. })
        ));

        let mut too_many_total_entries = sample_synthetic_config();
        let per_reg = MAX_CONFIG_ENTRIES_PER_REGISTRY;
        let regs_needed = (MAX_CONFIG_TOTAL_REGISTRY_ENTRIES / per_reg) + 1;
        too_many_total_entries.registries = (0..regs_needed)
            .map(|r| RegistrySkeleton {
                id: format!("ferrite:reg_{r}"),
                entries: (0..per_reg).map(|e| format!("ferrite:e_{e}")).collect(),
            })
            .collect();
        assert!(matches!(
            too_many_total_entries.validate(),
            Err(ConfigDataError::TooManyTotalRegistryEntries { .. })
        ));

        let mut too_many_tag_regs = sample_synthetic_config();
        too_many_tag_regs.tags = (0..=MAX_CONFIG_TAG_REGISTRIES)
            .map(|i| TagRegistryEntry {
                registry: format!("ferrite:static_{i}"),
                tags: Vec::new(),
            })
            .collect();
        assert!(matches!(
            too_many_tag_regs.validate(),
            Err(ConfigDataError::TooManyTagRegistries { .. })
        ));

        let mut too_many_total_indices = sample_synthetic_config();
        let per_tag = MAX_CONFIG_INDICES_PER_TAG;
        let tags_needed = (MAX_CONFIG_TOTAL_TAG_INDICES / per_tag) + 1;
        too_many_total_indices.tags = vec![TagRegistryEntry {
            registry: "ferrite:test_static_registry".to_owned(),
            tags: (0..tags_needed)
                .map(|t| TagGroupEntry {
                    id: format!("ferrite:t_{t}"),
                    entries: vec![0; per_tag],
                })
                .collect(),
        }];
        assert!(matches!(
            too_many_total_indices.validate(),
            Err(ConfigDataError::TooManyTotalTagIndices { .. })
        ));

        // Unknown JSON field must be rejected (`deny_unknown_fields`).
        let unknown_field = br#"{"protocol_version":777,"feature_flags":[],"known_packs":[],"registries":[],"tags":[],"extra":1}"#;
        assert!(matches!(
            ConfigurationData::from_json_bytes(unknown_field),
            Err(ConfigDataError::Json(_))
        ));
    }

    #[test]
    fn rejects_out_of_bounds_and_negative_tag_indices() {
        // Dynamic registry `ferrite:test_registry` has 2 entries (valid indices 0..=1); index 2 must fail.
        let mut bad_dyn = sample_synthetic_config();
        bad_dyn.tags[0].tags[0].entries = vec![0, 2];
        assert!(matches!(
            bad_dyn.validate(),
            Err(ConfigDataError::DynamicTagIndexOutOfBounds {
                index: 2,
                entry_count: 2
            })
        ));

        // Negative index must fail.
        let mut neg = sample_synthetic_config();
        neg.tags[1].tags[0].entries = vec![-1];
        assert!(matches!(
            neg.validate(),
            Err(ConfigDataError::NegativeTagIndex { value: -1 })
        ));

        // Static registry index above MAX_CONFIG_STATIC_TAG_INDEX must fail.
        let mut bad_static = sample_synthetic_config();
        bad_static.tags[1].tags[0].entries = vec![MAX_CONFIG_STATIC_TAG_INDEX + 1];
        assert!(matches!(
            bad_static.validate(),
            Err(ConfigDataError::StaticTagIndexOutOfBounds {
                index,
                max: MAX_CONFIG_STATIC_TAG_INDEX
            }) if index == MAX_CONFIG_STATIC_TAG_INDEX + 1
        ));
    }
}
