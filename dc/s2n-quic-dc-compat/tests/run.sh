#!/usr/bin/env bash
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# dcQUIC cross-version compatibility test runner.
#
# Usage:
#   ./tests/run.sh                          # build and test
#   ./tests/run.sh --skip-build             # test only (binaries already built)
#   PROTOCOLS="tcp" SCENARIOS="echo" ./tests/run.sh  # subset of tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$COMPAT_DIR/../.." && pwd)"

CURRENT_BIN="${CURRENT_BIN:-}"
PREVIOUS_BIN="${PREVIOUS_BIN:-}"
PROTOCOLS="${PROTOCOLS:-tcp udp}"
SCENARIOS="${SCENARIOS:-echo large-echo bidirectional}"
TIMEOUT="${TIMEOUT:-60}"

PASS=0
FAIL=0

# -- Build --

if [[ "${1:-}" != "--skip-build" ]]; then
    echo "=== Building current version ==="
    cargo build --release --manifest-path "$COMPAT_DIR/Cargo.toml"
    CURRENT_BIN="$REPO_ROOT/target/release/dcquic-compat"

    echo "=== Building previous version ==="
    cargo build --release --manifest-path "$COMPAT_DIR/previous/Cargo.toml"
    PREVIOUS_BIN="$COMPAT_DIR/previous/target/release/dcquic-compat-previous"
fi

if [[ -z "$CURRENT_BIN" || -z "$PREVIOUS_BIN" ]]; then
    echo "ERROR: CURRENT_BIN and PREVIOUS_BIN must be set with --skip-build"
    exit 1
fi

echo "Current binary:  $CURRENT_BIN"
echo "Previous binary: $PREVIOUS_BIN"
echo ""

# -- Test runner --

run_test() {
    local server_bin="$1"
    local client_bin="$2"
    local label="$3"
    local protocol="$4"
    local scenario="$5"

    local test_name="$label / $protocol / $scenario"
    echo -n "  $test_name ... "

    local server_out
    server_out=$(mktemp)

    # Start server
    "$server_bin" server --protocol "$protocol" > "$server_out" 2>&1 &
    local server_pid=$!

    # Wait for READY marker
    local ready=false
    for _ in $(seq 1 "$TIMEOUT"); do
        if grep -q "READY" "$server_out" 2>/dev/null; then
            ready=true
            break
        fi
        # Check if server died
        if ! kill -0 "$server_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    if [[ "$ready" != "true" ]]; then
        echo "FAIL (server not ready)"
        echo "  Server output:"
        cat "$server_out" | sed 's/^/    /'
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        rm -f "$server_out"
        FAIL=$((FAIL + 1))
        return
    fi

    local acceptor_addr
    local handshake_addr
    acceptor_addr=$(grep 'ACCEPTOR=' "$server_out" | head -1 | cut -d= -f2)
    handshake_addr=$(grep 'HANDSHAKE=' "$server_out" | head -1 | cut -d= -f2)

    # Run client
    local client_out
    client_out=$(mktemp)

    if timeout "$TIMEOUT" "$client_bin" client \
        --protocol "$protocol" \
        --addr "$acceptor_addr" \
        --handshake-addr "$handshake_addr" \
        --scenario "$scenario" > "$client_out" 2>&1; then

        if grep -q "SUCCESS" "$client_out"; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL (no SUCCESS marker)"
            echo "  Client output:"
            cat "$client_out" | sed 's/^/    /'
            FAIL=$((FAIL + 1))
        fi
    else
        echo "FAIL (exit code $?)"
        echo "  Client output:"
        cat "$client_out" | sed 's/^/    /'
        echo "  Server output:"
        cat "$server_out" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi

    # Cleanup
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -f "$server_out" "$client_out"
}

# -- Run tests --

echo "=== Cross-version compatibility tests ==="
echo ""

for protocol in $PROTOCOLS; do
    for scenario in $SCENARIOS; do
        run_test "$CURRENT_BIN"  "$PREVIOUS_BIN" "new-server + old-client" "$protocol" "$scenario"
        run_test "$PREVIOUS_BIN" "$CURRENT_BIN"  "old-server + new-client" "$protocol" "$scenario"
    done
done

echo ""
echo "--- Sanity check ---"
for protocol in $PROTOCOLS; do
    run_test "$CURRENT_BIN" "$CURRENT_BIN" "new-server + new-client" "$protocol" "echo"
done

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
