//! Strict `Configuration` skeleton extraction from `.rec` captures into gitignored JSON.

use std::collections::HashSet;
use std::path::Path;

use ferrite_protocol::codec::{
    decode_frame, decode_varint_prefix, read_bool, read_string, read_varint,
};
use ferrite_protocol::config_data::{
    is_valid_identifier, MAX_CONFIG_ENTRIES_PER_REGISTRY, MAX_CONFIG_FEATURE_FLAGS,
    MAX_CONFIG_INDICES_PER_TAG, MAX_CONFIG_KNOWN_PACKS, MAX_CONFIG_REGISTRIES,
    MAX_CONFIG_TAGS_PER_REGISTRY, MAX_CONFIG_TAG_REGISTRIES, MAX_IDENTIFIER_LEN,
    MAX_KNOWN_PACK_FIELD_LEN,
};
use ferrite_protocol::{
    decode_exact, ConfigDataError, ConfigurationData, ConnectionState, HandshakePacket, Intent,
    KnownPackEntry, Packet, ProtocolError, RegistrySkeleton, TagGroupEntry, TagRegistryEntry,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    parse_recording, Direction, RecordedEntry, RecorderError, C2S_FINISH_CONFIG_ID,
    MAX_RECORD_FILE_BYTES, S2C_FINISH_CONFIG_ID,
};

/// Maximum `.rec` file size accepted by the offline configuration extractor (`16 MiB`).
pub const MAX_EXTRACT_REC_BYTES: u64 = MAX_RECORD_FILE_BYTES;

// Observed 26.3 (`protocol 777`) `Configuration` packet IDs (verified on both Vanilla 26.3
// `session-1795852732-4.rec` and Purpur 26.3 `session-1795776728-3.rec`).
// TODO(verify): Packet names other than Finish Configuration are inferred from order, sizes,
// and 26.1 schema (+1 S2C shift) and will be confirmed against the live 26.3 client in Stage 2.3.
const C2S_CONFIG_CLIENT_INFO_ID: i32 = 0x00;
const C2S_CONFIG_CUSTOM_PAYLOAD_ID: i32 = 0x02;
const C2S_CONFIG_SELECT_KNOWN_PACKS_ID: i32 = 0x07;
const S2C_CONFIG_CUSTOM_PAYLOAD_ID: i32 = 0x01;
const S2C_CONFIG_REGISTRY_DATA_ID: i32 = 0x07;
const S2C_CONFIG_FEATURE_FLAGS_ID: i32 = 0x0d;
const S2C_CONFIG_UPDATE_TAGS_ID: i32 = 0x0e;
const S2C_CONFIG_SELECT_KNOWN_PACKS_ID: i32 = 0x0f;
const MAX_CUSTOM_PAYLOAD_BYTES: usize = 32_767;
const MAX_NBT_SKIP_DEPTH: usize = 512;

/// Numeric-only summary emitted when extracting a `Configuration` skeleton from `.rec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionStats {
    pub feature_flags_count: usize,
    pub known_packs_count: usize,
    pub registries_count: usize,
    pub total_registry_entries: usize,
    pub registries_with_has_data_true: usize,
    pub entries_with_has_data_true: usize,
    pub update_tags_registries_count: usize,
    pub static_tag_registries_count: usize,
    pub total_tags: usize,
    pub total_tag_indices: usize,
}

impl ExtractionStats {
    /// Formats numeric-only summary (never includes registry, entry, or tag identifiers).
    #[must_use]
    pub fn format_counts_only(&self) -> String {
        format!(
            "extracted configuration counts:\n  feature_flags: {}\n  known_packs: {}\n  registries: {}\n  total_registry_entries: {}\n  registries_with_has_data_true: {}\n  entries_with_has_data_true: {}\n  update_tags_registries: {}\n  static_tag_registries (not in Registry Data): {}\n  total_tags: {}\n  total_tag_indices: {}\n",
            self.feature_flags_count,
            self.known_packs_count,
            self.registries_count,
            self.total_registry_entries,
            self.registries_with_has_data_true,
            self.entries_with_has_data_true,
            self.update_tags_registries_count,
            self.static_tag_registries_count,
            self.total_tags,
            self.total_tag_indices,
        )
    }
}

/// Verifies via `git check-ignore` that `path` is ignored by git before writing.
pub fn ensure_git_ignored(path: &Path) -> Result<(), RecorderError> {
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let existing_dir = full_path
        .ancestors()
        .find(|p| p.is_dir())
        .ok_or_else(|| RecorderError::OutputNotGitIgnored(path.to_path_buf()))?;

    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(existing_dir)
        .args(["check-ignore", "-q", "--"])
        .arg(&full_path)
        .status()
        .map_err(|_| RecorderError::OutputNotGitIgnored(path.to_path_buf()))?;

    if status.code() == Some(0) {
        Ok(())
    } else {
        Err(RecorderError::OutputNotGitIgnored(path.to_path_buf()))
    }
}

fn read_identifier_strict(input: &mut &[u8]) -> Result<String, RecorderError> {
    let value = read_string(input, MAX_IDENTIFIER_LEN)?;
    if !is_valid_identifier(&value) {
        return Err(RecorderError::ConfigValidation(
            ConfigDataError::InvalidIdentifier(value),
        ));
    }
    Ok(value)
}

fn read_bounded_count(
    input: &mut &[u8],
    max: usize,
    ctx: &'static str,
) -> Result<usize, RecorderError> {
    let raw = read_varint(input)?;
    if raw < 0 {
        return Err(RecorderError::Protocol(ProtocolError::NegativeLength(raw)));
    }
    let count = raw as usize;
    if count > max {
        return Err(RecorderError::StrictExtract(format!(
            "{ctx} count {count} exceeds maximum {max}"
        )));
    }
    if count > input.len() {
        return Err(RecorderError::Protocol(ProtocolError::UnexpectedEof));
    }
    Ok(count)
}

fn ensure_no_trailing(slice: &[u8]) -> Result<(), RecorderError> {
    if !slice.is_empty() {
        return Err(RecorderError::Protocol(ProtocolError::TrailingBytes(
            slice.len(),
        )));
    }
    Ok(())
}

fn decode_known_packs_payload(mut input: &[u8]) -> Result<Vec<KnownPackEntry>, RecorderError> {
    let count = read_bounded_count(&mut input, MAX_CONFIG_KNOWN_PACKS, "known_packs")?;
    let mut packs = Vec::with_capacity(count);
    for _ in 0..count {
        let namespace = read_string(&mut input, MAX_KNOWN_PACK_FIELD_LEN)?;
        let id = read_string(&mut input, MAX_KNOWN_PACK_FIELD_LEN)?;
        let version = read_string(&mut input, MAX_KNOWN_PACK_FIELD_LEN)?;
        packs.push(KnownPackEntry {
            namespace,
            id,
            version,
        });
    }
    ensure_no_trailing(input)?;
    Ok(packs)
}

fn take_n<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], RecorderError> {
    if input.len() < n {
        return Err(RecorderError::Protocol(ProtocolError::UnexpectedEof));
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}

fn skip_nbt_payload(tag_type: u8, input: &mut &[u8], depth: usize) -> Result<(), RecorderError> {
    if depth > MAX_NBT_SKIP_DEPTH {
        return Err(RecorderError::StrictExtract(
            "embedded NBT exceeded maximum nesting depth".to_owned(),
        ));
    }
    match tag_type {
        0 => Ok(()),
        1 => {
            take_n(input, 1)?;
            Ok(())
        }
        2 => {
            take_n(input, 2)?;
            Ok(())
        }
        3 | 5 => {
            take_n(input, 4)?;
            Ok(())
        }
        4 | 6 => {
            take_n(input, 8)?;
            Ok(())
        }
        7 => {
            let b = take_n(input, 4)?;
            let len = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if len < 0 {
                return Err(RecorderError::StrictExtract(
                    "negative NBT ByteArray length".to_owned(),
                ));
            }
            take_n(input, len as usize)?;
            Ok(())
        }
        8 => {
            let b = take_n(input, 2)?;
            let len = u16::from_be_bytes([b[0], b[1]]) as usize;
            take_n(input, len)?;
            Ok(())
        }
        9 => {
            let elem_type = take_n(input, 1)?[0];
            let b = take_n(input, 4)?;
            let len = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if len < 0 {
                return Err(RecorderError::StrictExtract(
                    "negative NBT List length".to_owned(),
                ));
            }
            if len > 0 && elem_type == 0 {
                return Err(RecorderError::StrictExtract(
                    "non-empty NBT List with TAG_End element type".to_owned(),
                ));
            }
            for _ in 0..(len as usize) {
                skip_nbt_payload(elem_type, input, depth + 1)?;
            }
            Ok(())
        }
        10 => loop {
            let field_type = take_n(input, 1)?[0];
            if field_type == 0 {
                return Ok(());
            }
            let name_len_bytes = take_n(input, 2)?;
            let name_len = u16::from_be_bytes([name_len_bytes[0], name_len_bytes[1]]) as usize;
            take_n(input, name_len)?;
            skip_nbt_payload(field_type, input, depth + 1)?;
        },
        11 => {
            let b = take_n(input, 4)?;
            let len = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if len < 0 {
                return Err(RecorderError::StrictExtract(
                    "negative NBT IntArray length".to_owned(),
                ));
            }
            let byte_len = (len as usize)
                .checked_mul(4)
                .ok_or_else(|| RecorderError::StrictExtract("NBT IntArray overflow".to_owned()))?;
            take_n(input, byte_len)?;
            Ok(())
        }
        12 => {
            let b = take_n(input, 4)?;
            let len = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if len < 0 {
                return Err(RecorderError::StrictExtract(
                    "negative NBT LongArray length".to_owned(),
                ));
            }
            let byte_len = (len as usize)
                .checked_mul(8)
                .ok_or_else(|| RecorderError::StrictExtract("NBT LongArray overflow".to_owned()))?;
            take_n(input, byte_len)?;
            Ok(())
        }
        other => Err(RecorderError::StrictExtract(format!(
            "unknown network NBT tag type {other:#04x}"
        ))),
    }
}

fn skip_network_nbt_root(input: &mut &[u8]) -> Result<(), RecorderError> {
    let root_type = take_n(input, 1)?[0];
    skip_nbt_payload(root_type, input, 0)
}

/// Strictly decodes `Configuration` frames from parsed `.rec` entries into [`ConfigurationData`].
pub fn extract_configuration_from_entries(
    entries: &[RecordedEntry],
) -> Result<(ConfigurationData, ExtractionStats), RecorderError> {
    let mut saw_handshake_777 = false;
    let mut feature_flags: Option<Vec<String>> = None;
    let mut known_packs: Option<Vec<KnownPackEntry>> = None;
    let mut registries: Vec<RegistrySkeleton> = Vec::new();
    let mut update_tags: Option<Vec<TagRegistryEntry>> = None;
    let mut saw_s2c_finish = false;
    let mut saw_c2s_finish = false;

    let mut total_registry_entries: usize = 0;
    let mut registries_with_has_data_true: usize = 0;
    let mut entries_with_has_data_true: usize = 0;
    let mut total_tags: usize = 0;
    let mut total_tag_indices: usize = 0;

    for entry in entries {
        let Some((raw_body_len, prefix_len)) = decode_varint_prefix(&entry.raw_frame)? else {
            return Err(RecorderError::Protocol(ProtocolError::UnexpectedEof));
        };
        if raw_body_len < 0 {
            return Err(RecorderError::Protocol(ProtocolError::NegativeLength(
                raw_body_len,
            )));
        }
        let body_len = raw_body_len as usize;
        if prefix_len + body_len != entry.raw_frame.len() {
            return Err(RecorderError::StrictExtract(format!(
                "seq #{}: frame length prefix ({body_len}) does not match raw bytes",
                entry.seq
            )));
        }
        let body = &entry.raw_frame[prefix_len..];
        let (packet_id, payload) = decode_frame(body)?;

        match (entry.direction, entry.state, packet_id) {
            (Direction::C2S, ConnectionState::Handshaking, HandshakePacket::ID) => {
                let hs: HandshakePacket = decode_exact(payload)?;
                if hs.protocol_version != PROTOCOL_VERSION {
                    return Err(RecorderError::ConfigValidation(
                        ConfigDataError::WrongProtocolVersion {
                            found: hs.protocol_version,
                            expected: PROTOCOL_VERSION,
                        },
                    ));
                }
                if hs.next_state != Intent::Login {
                    return Err(RecorderError::StrictExtract(
                        "recording Handshake intent is not Login".to_owned(),
                    ));
                }
                saw_handshake_777 = true;
            }
            (_, ConnectionState::Login, _) => {}
            (Direction::S2C, ConnectionState::Configuration, S2C_CONFIG_CUSTOM_PAYLOAD_ID) => {
                let mut slice = payload;
                let channel = read_identifier_strict(&mut slice)?;
                if slice.len() > MAX_CUSTOM_PAYLOAD_BYTES {
                    return Err(RecorderError::StrictExtract(
                        "S2C Custom Payload exceeds 32767 bytes".to_owned(),
                    ));
                }
                if channel.ends_with(":brand") {
                    let _brand = read_string(&mut slice, MAX_CUSTOM_PAYLOAD_BYTES)?;
                    ensure_no_trailing(slice)?;
                }
            }
            (Direction::C2S, ConnectionState::Configuration, C2S_CONFIG_CUSTOM_PAYLOAD_ID) => {
                let mut slice = payload;
                let _channel = read_identifier_strict(&mut slice)?;
                if slice.len() > MAX_CUSTOM_PAYLOAD_BYTES {
                    return Err(RecorderError::StrictExtract(
                        "C2S Custom Payload exceeds 32767 bytes".to_owned(),
                    ));
                }
            }
            (Direction::C2S, ConnectionState::Configuration, C2S_CONFIG_CLIENT_INFO_ID) => {
                if payload.is_empty() || payload.len() > 256 {
                    return Err(RecorderError::StrictExtract(format!(
                        "invalid C2S Client Information payload length {}",
                        payload.len()
                    )));
                }
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_CONFIG_FEATURE_FLAGS_ID) => {
                if feature_flags.is_some() {
                    return Err(RecorderError::StrictExtract(
                        "duplicate S2C Feature Flags (0x0d) frame".to_owned(),
                    ));
                }
                let mut slice = payload;
                let count =
                    read_bounded_count(&mut slice, MAX_CONFIG_FEATURE_FLAGS, "feature_flags")?;
                let mut flags = Vec::with_capacity(count);
                for _ in 0..count {
                    flags.push(read_identifier_strict(&mut slice)?);
                }
                ensure_no_trailing(slice)?;
                feature_flags = Some(flags);
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_CONFIG_SELECT_KNOWN_PACKS_ID) => {
                if known_packs.is_some() {
                    return Err(RecorderError::StrictExtract(
                        "duplicate S2C Select Known Packs (0x0f) frame".to_owned(),
                    ));
                }
                known_packs = Some(decode_known_packs_payload(payload)?);
            }
            (Direction::C2S, ConnectionState::Configuration, C2S_CONFIG_SELECT_KNOWN_PACKS_ID) => {
                let _client_packs = decode_known_packs_payload(payload)?;
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_CONFIG_REGISTRY_DATA_ID) => {
                if registries.len() >= MAX_CONFIG_REGISTRIES {
                    return Err(RecorderError::ConfigValidation(
                        ConfigDataError::TooManyRegistries {
                            len: registries.len() + 1,
                            max: MAX_CONFIG_REGISTRIES,
                        },
                    ));
                }
                let mut slice = payload;
                let reg_id = read_identifier_strict(&mut slice)?;
                let entry_count = read_bounded_count(
                    &mut slice,
                    MAX_CONFIG_ENTRIES_PER_REGISTRY,
                    "registry entries",
                )?;
                let mut entries_vec = Vec::with_capacity(entry_count);
                let mut reg_had_data = false;

                for _ in 0..entry_count {
                    let entry_id = read_identifier_strict(&mut slice)?;
                    let has_data = read_bool(&mut slice)?;
                    total_registry_entries = total_registry_entries.saturating_add(1);
                    if has_data {
                        reg_had_data = true;
                        entries_with_has_data_true = entries_with_has_data_true.saturating_add(1);
                        skip_network_nbt_root(&mut slice)?;
                    }
                    entries_vec.push(entry_id);
                }
                ensure_no_trailing(slice)?;
                if reg_had_data {
                    registries_with_has_data_true = registries_with_has_data_true.saturating_add(1);
                }
                registries.push(RegistrySkeleton {
                    id: reg_id,
                    entries: entries_vec,
                });
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_CONFIG_UPDATE_TAGS_ID) => {
                if update_tags.is_some() {
                    return Err(RecorderError::StrictExtract(
                        "duplicate S2C Update Tags (0x0e) frame".to_owned(),
                    ));
                }
                let mut slice = payload;
                let reg_count =
                    read_bounded_count(&mut slice, MAX_CONFIG_TAG_REGISTRIES, "tag registries")?;
                let mut tag_regs = Vec::with_capacity(reg_count);
                for _ in 0..reg_count {
                    let registry = read_identifier_strict(&mut slice)?;
                    let tag_count =
                        read_bounded_count(&mut slice, MAX_CONFIG_TAGS_PER_REGISTRY, "tags")?;
                    let mut groups = Vec::with_capacity(tag_count);
                    for _ in 0..tag_count {
                        let id = read_identifier_strict(&mut slice)?;
                        let idx_count = read_bounded_count(
                            &mut slice,
                            MAX_CONFIG_INDICES_PER_TAG,
                            "tag indices",
                        )?;
                        let mut indices = Vec::with_capacity(idx_count);
                        for _ in 0..idx_count {
                            let idx = read_varint(&mut slice)?;
                            if idx < 0 {
                                return Err(RecorderError::ConfigValidation(
                                    ConfigDataError::NegativeTagIndex { value: idx },
                                ));
                            }
                            indices.push(idx);
                        }
                        total_tags = total_tags.saturating_add(1);
                        total_tag_indices = total_tag_indices.saturating_add(indices.len());
                        groups.push(TagGroupEntry {
                            id,
                            entries: indices,
                        });
                    }
                    tag_regs.push(TagRegistryEntry {
                        registry,
                        tags: groups,
                    });
                }
                ensure_no_trailing(slice)?;
                update_tags = Some(tag_regs);
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_FINISH_CONFIG_ID) => {
                if saw_s2c_finish {
                    return Err(RecorderError::StrictExtract(
                        "duplicate S2C Finish Configuration (0x03)".to_owned(),
                    ));
                }
                ensure_no_trailing(payload)?;
                saw_s2c_finish = true;
            }
            (Direction::C2S, ConnectionState::Configuration, C2S_FINISH_CONFIG_ID) => {
                if saw_c2s_finish {
                    return Err(RecorderError::StrictExtract(
                        "duplicate C2S Acknowledge Finish Configuration (0x03)".to_owned(),
                    ));
                }
                ensure_no_trailing(payload)?;
                saw_c2s_finish = true;
            }
            (dir, state, id) => {
                return Err(RecorderError::StrictExtract(format!(
                    "unexpected packet {} {state:?} {id:#04x}",
                    dir.as_str()
                )));
            }
        }
    }

    if !saw_handshake_777 {
        return Err(RecorderError::StrictExtract(
            "recording does not contain a valid protocol 777 Login handshake".to_owned(),
        ));
    }
    if !saw_s2c_finish || !saw_c2s_finish {
        return Err(RecorderError::StrictExtract(
            "recording did not complete Finish Configuration (0x03 / 0x03)".to_owned(),
        ));
    }
    if registries.is_empty() {
        return Err(RecorderError::StrictExtract(
            "recording contained zero Registry Data (0x07) packets".to_owned(),
        ));
    }

    let registries_count = registries.len();
    if entries_with_has_data_true > 0 {
        return Err(RecorderError::EmbeddedNbtUnsupported {
            registries_count,
            total_registry_entries,
            registries_with_has_data_true,
            entries_with_has_data_true,
        });
    }

    let feature_flags = feature_flags.ok_or_else(|| {
        RecorderError::StrictExtract("missing S2C Feature Flags (0x0d) frame".to_owned())
    })?;
    let known_packs = known_packs.ok_or_else(|| {
        RecorderError::StrictExtract("missing S2C Select Known Packs (0x0f) frame".to_owned())
    })?;
    let tags = update_tags.ok_or_else(|| {
        RecorderError::StrictExtract("missing S2C Update Tags (0x0e) frame".to_owned())
    })?;

    let dynamic_ids: HashSet<&str> = registries.iter().map(|r| r.id.as_str()).collect();
    let static_tag_registries_count = tags
        .iter()
        .filter(|tr| !dynamic_ids.contains(tr.registry.as_str()))
        .count();

    let stats = ExtractionStats {
        feature_flags_count: feature_flags.len(),
        known_packs_count: known_packs.len(),
        registries_count,
        total_registry_entries,
        registries_with_has_data_true,
        entries_with_has_data_true,
        update_tags_registries_count: tags.len(),
        static_tag_registries_count,
        total_tags,
        total_tag_indices,
    };

    let config = ConfigurationData {
        protocol_version: PROTOCOL_VERSION,
        feature_flags,
        known_packs,
        registries,
        tags,
    };
    config.validate()?;

    Ok((config, stats))
}

/// Extracts [`ConfigurationData`] from `rec_path` and writes JSON atomically to `out_path`.
pub async fn extract_config_file(
    rec_path: &Path,
    out_path: &Path,
    overwrite: bool,
) -> Result<ExtractionStats, RecorderError> {
    ensure_git_ignored(out_path)?;

    let meta = tokio::fs::metadata(rec_path).await?;
    if meta.len() > MAX_EXTRACT_REC_BYTES {
        return Err(RecorderError::InputRecordingTooLarge {
            len: meta.len(),
            max: MAX_EXTRACT_REC_BYTES,
        });
    }

    let rec_file = tokio::fs::File::open(rec_path).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    rec_file
        .take(MAX_EXTRACT_REC_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_EXTRACT_REC_BYTES {
        return Err(RecorderError::InputRecordingTooLarge {
            len: bytes.len() as u64,
            max: MAX_EXTRACT_REC_BYTES,
        });
    }

    let entries = parse_recording(&bytes)?;
    let (config, stats) = extract_configuration_from_entries(&entries)?;
    let mut json = config.to_json_pretty()?;
    json.push('\n');

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    if overwrite {
        let tmp_name = format!(
            "{}.tmp.{}",
            out_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.json"),
            std::process::id()
        );
        let tmp_path = out_path.with_file_name(tmp_name);
        let mut tmp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        let write_res: Result<(), std::io::Error> = async {
            tmp_file.write_all(json.as_bytes()).await?;
            tmp_file.flush().await?;
            tmp_file.sync_all().await?;
            drop(tmp_file);
            tokio::fs::rename(&tmp_path, out_path).await
        }
        .await;
        if let Err(err) = write_res {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(RecorderError::Io(err));
        }
    } else {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out_path)
            .await?;
        let write_res: Result<(), std::io::Error> = async {
            file.write_all(json.as_bytes()).await?;
            file.flush().await?;
            file.sync_all().await
        }
        .await;
        if let Err(err) = write_res {
            drop(file);
            let _ = tokio::fs::remove_file(out_path).await;
            return Err(RecorderError::Io(err));
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{state_to_u8, REC_MAGIC};
    use ferrite_protocol::codec::{encode_frame, write_bool, write_string, write_varint};

    fn push_rec_entry(
        buf: &mut Vec<u8>,
        seq: u64,
        dir: Direction,
        state: ConnectionState,
        packet_id: i32,
        payload: &[u8],
    ) {
        let raw_frame = encode_frame(packet_id, payload).unwrap();
        let raw_len = u32::try_from(raw_frame.len()).unwrap();
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.push(dir as u8);
        buf.push(state_to_u8(state));
        buf.extend_from_slice(&raw_len.to_be_bytes());
        buf.extend_from_slice(&raw_frame);
    }

    fn build_synthetic_valid_rec() -> Vec<u8> {
        let mut rec = Vec::from(REC_MAGIC);
        let mut hs_payload = Vec::new();
        HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25566,
            next_state: Intent::Login,
        }
        .encode(&mut hs_payload)
        .unwrap();
        push_rec_entry(
            &mut rec,
            0,
            Direction::C2S,
            ConnectionState::Handshaking,
            0x00,
            &hs_payload,
        );

        push_rec_entry(
            &mut rec,
            1,
            Direction::C2S,
            ConnectionState::Login,
            0x03,
            &[],
        );

        let mut brand = Vec::new();
        write_string("ferrite:brand", 32_767, &mut brand).unwrap();
        write_string("ferrite_test", 32_767, &mut brand).unwrap();
        push_rec_entry(
            &mut rec,
            2,
            Direction::C2S,
            ConnectionState::Configuration,
            0x02,
            &brand,
        );
        push_rec_entry(
            &mut rec,
            3,
            Direction::S2C,
            ConnectionState::Configuration,
            0x01,
            &brand,
        );

        let mut ff = Vec::new();
        write_varint(1, &mut ff);
        write_string("ferrite:test_flag", 32_767, &mut ff).unwrap();
        push_rec_entry(
            &mut rec,
            4,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0d,
            &ff,
        );

        let mut kp = Vec::new();
        write_varint(1, &mut kp);
        write_string("ferrite", 256, &mut kp).unwrap();
        write_string("test_core", 256, &mut kp).unwrap();
        write_string("26.3", 256, &mut kp).unwrap();
        push_rec_entry(
            &mut rec,
            5,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0f,
            &kp,
        );
        push_rec_entry(
            &mut rec,
            6,
            Direction::C2S,
            ConnectionState::Configuration,
            0x07,
            &kp,
        );

        let mut reg_a = Vec::new();
        write_string("ferrite:test_reg_a", 32_767, &mut reg_a).unwrap();
        write_varint(2, &mut reg_a);
        write_string("ferrite:test_entry_0", 32_767, &mut reg_a).unwrap();
        write_bool(false, &mut reg_a);
        write_string("ferrite:test_entry_1", 32_767, &mut reg_a).unwrap();
        write_bool(false, &mut reg_a);
        push_rec_entry(
            &mut rec,
            7,
            Direction::S2C,
            ConnectionState::Configuration,
            0x07,
            &reg_a,
        );

        let mut tags = Vec::new();
        write_varint(2, &mut tags);
        write_string("ferrite:test_reg_a", 32_767, &mut tags).unwrap();
        write_varint(1, &mut tags);
        write_string("ferrite:test_dyn_tag", 32_767, &mut tags).unwrap();
        write_varint(2, &mut tags);
        write_varint(0, &mut tags);
        write_varint(1, &mut tags);

        write_string("ferrite:test_static_block", 32_767, &mut tags).unwrap();
        write_varint(1, &mut tags);
        write_string("ferrite:test_static_tag", 32_767, &mut tags).unwrap();
        write_varint(2, &mut tags);
        write_varint(3, &mut tags);
        write_varint(7, &mut tags);
        push_rec_entry(
            &mut rec,
            8,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0e,
            &tags,
        );

        push_rec_entry(
            &mut rec,
            9,
            Direction::S2C,
            ConnectionState::Configuration,
            0x03,
            &[],
        );
        push_rec_entry(
            &mut rec,
            10,
            Direction::C2S,
            ConnectionState::Configuration,
            0x03,
            &[],
        );
        rec
    }

    #[tokio::test]
    async fn extracts_synthetic_configuration_skeleton_and_counts_only_numbers() {
        let rec_bytes = build_synthetic_valid_rec();
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let test_dir = workspace_root.join("target").join("test-recorder-extract");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();
        let rec_path = test_dir.join("synthetic.rec");
        let out_path = test_dir.join("synthetic-config.json");
        let _ = tokio::fs::remove_file(&out_path).await;
        tokio::fs::write(&rec_path, &rec_bytes).await.unwrap();

        let stats = extract_config_file(&rec_path, &out_path, false)
            .await
            .unwrap();
        assert_eq!(stats.feature_flags_count, 1);
        assert_eq!(stats.known_packs_count, 1);
        assert_eq!(stats.registries_count, 1);
        assert_eq!(stats.total_registry_entries, 2);
        assert_eq!(stats.registries_with_has_data_true, 0);
        assert_eq!(stats.entries_with_has_data_true, 0);
        assert_eq!(stats.update_tags_registries_count, 2);
        assert_eq!(stats.static_tag_registries_count, 1);
        assert_eq!(stats.total_tags, 2);
        assert_eq!(stats.total_tag_indices, 4);

        let summary = stats.format_counts_only();
        assert!(!summary.contains("ferrite:test_flag"));
        assert!(!summary.contains("test_core"));
        assert!(!summary.contains("ferrite:test_reg_a"));
        assert!(!summary.contains("ferrite:test_entry_0"));
        assert!(!summary.contains("ferrite:test_static_block"));

        let written = tokio::fs::read(&out_path).await.unwrap();
        let loaded = ConfigurationData::from_json_bytes(&written).unwrap();
        assert_eq!(loaded.registries[0].id, "ferrite:test_reg_a");
        assert_eq!(
            loaded.registries[0].entries,
            vec!["ferrite:test_entry_0", "ferrite:test_entry_1"]
        );
        assert_eq!(loaded.tags[1].registry, "ferrite:test_static_block");
        assert_eq!(loaded.tags[1].tags[0].entries, vec![3, 7]);

        // Second run without overwrite must fail atomically (`create_new` -> AlreadyExists).
        let dup_err = extract_config_file(&rec_path, &out_path, false)
            .await
            .unwrap_err();
        assert!(
            matches!(dup_err, RecorderError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "expected AlreadyExists on duplicate create_new, got {dup_err:?}"
        );

        let _ = tokio::fs::remove_dir_all(&test_dir).await;
    }

    #[tokio::test]
    async fn extract_rejects_non_gitignored_output_path_without_writing() {
        let rec_bytes = build_synthetic_valid_rec();
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let test_dir = workspace_root
            .join("target")
            .join("test-recorder-ignore-guard");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();
        let rec_path = test_dir.join("synthetic.rec");
        tokio::fs::write(&rec_path, &rec_bytes).await.unwrap();

        let non_ignored_out = workspace_root
            .join("crates")
            .join("forbidden-unignored-config.json");
        let _ = tokio::fs::remove_file(&non_ignored_out).await;

        let res = extract_config_file(&rec_path, &non_ignored_out, false).await;
        assert!(
            matches!(res, Err(RecorderError::OutputNotGitIgnored(_))),
            "expected OutputNotGitIgnored, got {res:?}"
        );
        assert!(
            !non_ignored_out.exists(),
            "non-gitignored output file must never be created"
        );

        let _ = tokio::fs::remove_dir_all(&test_dir).await;
    }

    #[tokio::test]
    async fn extract_rejects_corrupt_frame_and_has_data_true_without_writing() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let test_dir = workspace_root.join("target").join("test-recorder-corrupt");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();

        let mut corrupt_rec = Vec::from(REC_MAGIC);
        let mut hs_payload = Vec::new();
        HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25566,
            next_state: Intent::Login,
        }
        .encode(&mut hs_payload)
        .unwrap();
        push_rec_entry(
            &mut corrupt_rec,
            0,
            Direction::C2S,
            ConnectionState::Handshaking,
            0x00,
            &hs_payload,
        );
        push_rec_entry(
            &mut corrupt_rec,
            1,
            Direction::C2S,
            ConnectionState::Login,
            0x03,
            &[],
        );
        let mut bad_ff = Vec::new();
        write_varint(1, &mut bad_ff);
        write_string("ferrite:test_flag", 32_767, &mut bad_ff).unwrap();
        bad_ff.push(0x99);
        push_rec_entry(
            &mut corrupt_rec,
            2,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0d,
            &bad_ff,
        );

        let corrupt_rec_path = test_dir.join("corrupt.rec");
        let corrupt_out_path = test_dir.join("must-not-exist-corrupt.json");
        let _ = tokio::fs::remove_file(&corrupt_out_path).await;
        tokio::fs::write(&corrupt_rec_path, &corrupt_rec)
            .await
            .unwrap();

        let corrupt_res = extract_config_file(&corrupt_rec_path, &corrupt_out_path, false).await;
        assert!(
            matches!(
                corrupt_res,
                Err(RecorderError::Protocol(ProtocolError::TrailingBytes(1)))
            ),
            "expected TrailingBytes(1) on corrupt Feature Flags frame, got {corrupt_res:?}"
        );
        assert!(
            !corrupt_out_path.exists(),
            "corrupt recording must not produce an output JSON file"
        );

        let mut nbt_rec = Vec::from(REC_MAGIC);
        push_rec_entry(
            &mut nbt_rec,
            0,
            Direction::C2S,
            ConnectionState::Handshaking,
            0x00,
            &hs_payload,
        );
        push_rec_entry(
            &mut nbt_rec,
            1,
            Direction::C2S,
            ConnectionState::Login,
            0x03,
            &[],
        );
        let mut ff = Vec::new();
        write_varint(1, &mut ff);
        write_string("ferrite:test_flag", 32_767, &mut ff).unwrap();
        push_rec_entry(
            &mut nbt_rec,
            2,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0d,
            &ff,
        );
        let mut kp = Vec::new();
        write_varint(1, &mut kp);
        write_string("ferrite", 256, &mut kp).unwrap();
        write_string("test_core", 256, &mut kp).unwrap();
        write_string("26.3", 256, &mut kp).unwrap();
        push_rec_entry(
            &mut nbt_rec,
            3,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0f,
            &kp,
        );
        let mut reg_nbt = Vec::new();
        write_string("ferrite:test_reg_nbt", 32_767, &mut reg_nbt).unwrap();
        write_varint(1, &mut reg_nbt);
        write_string("ferrite:test_entry_with_nbt", 32_767, &mut reg_nbt).unwrap();
        write_bool(true, &mut reg_nbt);
        reg_nbt.extend_from_slice(&[0x0a, 0x00]);
        push_rec_entry(
            &mut nbt_rec,
            4,
            Direction::S2C,
            ConnectionState::Configuration,
            0x07,
            &reg_nbt,
        );
        let mut empty_tags = Vec::new();
        write_varint(0, &mut empty_tags);
        push_rec_entry(
            &mut nbt_rec,
            5,
            Direction::S2C,
            ConnectionState::Configuration,
            0x0e,
            &empty_tags,
        );
        push_rec_entry(
            &mut nbt_rec,
            6,
            Direction::S2C,
            ConnectionState::Configuration,
            0x03,
            &[],
        );
        push_rec_entry(
            &mut nbt_rec,
            7,
            Direction::C2S,
            ConnectionState::Configuration,
            0x03,
            &[],
        );

        let nbt_rec_path = test_dir.join("nbt.rec");
        let nbt_out_path = test_dir.join("must-not-exist-nbt.json");
        let _ = tokio::fs::remove_file(&nbt_out_path).await;
        tokio::fs::write(&nbt_rec_path, &nbt_rec).await.unwrap();

        let nbt_res = extract_config_file(&nbt_rec_path, &nbt_out_path, false).await;
        assert!(matches!(
            nbt_res,
            Err(RecorderError::EmbeddedNbtUnsupported {
                registries_with_has_data_true: 1,
                entries_with_has_data_true: 1,
                ..
            })
        ));
        assert!(!nbt_out_path.exists());

        let _ = tokio::fs::remove_dir_all(&test_dir).await;
    }

    #[tokio::test]
    async fn extract_rejects_oversized_input_rec_file() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let test_dir = workspace_root
            .join("target")
            .join("test-recorder-oversize-rec");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();

        let huge_rec = test_dir.join("oversized.rec");
        let out_path = test_dir.join("must-not-exist-oversize.json");
        let _ = tokio::fs::remove_file(&out_path).await;

        {
            let f = std::fs::File::create(&huge_rec).unwrap();
            f.set_len(MAX_EXTRACT_REC_BYTES + 1).unwrap();
        }

        let res = extract_config_file(&huge_rec, &out_path, false).await;
        assert!(
            matches!(
                res,
                Err(RecorderError::InputRecordingTooLarge {
                    len,
                    max: MAX_EXTRACT_REC_BYTES,
                }) if len == MAX_EXTRACT_REC_BYTES + 1
            ),
            "expected InputRecordingTooLarge, got {res:?}"
        );
        assert!(!out_path.exists());

        let _ = tokio::fs::remove_dir_all(&test_dir).await;
    }
}
