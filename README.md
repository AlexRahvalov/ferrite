# Ferrite

Independent, clean-room, high-performance voxel sandbox server written in Rust.

## Target Protocol
- Version: **26.3** (protocol **777**)

## Workspace Crates
- `ferrite-nbt` — Named Binary Tag (NBT) reader/writer
- `ferrite-protocol` — wire codecs, packet definitions, connection states
- `ferrite-net` — async TCP networking layer (`tokio`)
- `ferrite-world` — chunks, Anvil storage, world generation
- `ferrite-server` — server binary, tick loop, entities, players, commands

Dependency direction: `ferrite-server` -> `ferrite-world`, `ferrite-net` -> `ferrite-protocol` -> `ferrite-nbt`.

## Development Checks
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Run
```bash
cargo run -p ferrite-server
```
