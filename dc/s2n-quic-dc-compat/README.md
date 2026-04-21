# dcQUIC Cross-Version Compatibility Tests

Tests that the current version of `s2n-quic-dc` can communicate with a previous version over the wire.

## How it works

Two binaries are built:
- `dcquic-compat` — built from the current workspace (path dependencies)
- `dcquic-compat-previous` — built from a pinned crates.io version (in `previous/`)

The test runner starts one as a server and the other as a client, then verifies they can complete a PSK handshake and exchange data.

## Running locally

```bash
# Build and run all tests
./tests/run.sh

# Run only TCP echo tests
PROTOCOLS="tcp" SCENARIOS="echo" ./tests/run.sh

# Skip build (if binaries are already built)
./tests/run.sh --skip-build
```

## Updating the previous version

1. Update `previous/Cargo.toml` dependency versions
2. If the API changed, update `previous/src/main.rs`

## Adding a new test scenario

1. Add a new match arm in `src/main.rs` (and `previous/src/main.rs`)
2. Add the scenario name to the `SCENARIOS` list in `tests/run.sh`
