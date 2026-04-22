#!/usr/bin/env bash
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# dcQUIC cross-version compatibility test runner.
# Builds both binaries and runs all test scenarios.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$COMPAT_DIR/../.." && pwd)"

PASS=0
FAIL=0
TIMEOUT=60

# -- Build --

echo "=== Building current version ==="
cargo build --release --manifest-path "$COMPAT_DIR/Cargo.toml"

echo "=== Building previous version ==="
cargo build --release --manifest-path "$COMPAT_DIR/previous/Cargo.toml"

CURRENT="$REPO_ROOT/target/release/dcquic-compat"
PREVIOUS="$COMPAT_DIR/previous/target/release/dcquic-compat-previous"

# -- Test runner --

run_test() {
    local server_bin="$1"
    local client_bin="$2"
    local label="$3"
    local protocol="$4"
    local scenario="$5"

    echo -n "  $label / $protocol / $scenario ... "

    local server_out
    server_out=$(mktemp)

    "$server_bin" server --protocol "$protocol" > "$server_out" 2>&1 &
    local server_pid=$!

    # Wait for READY
    local ready=false
    for _ in $(seq 1 "$TIMEOUT"); do
        if grep -q "READY" "$server_out" 2>/dev/null; then
            ready=true
            break
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
        sleep 0.1
    done

    if [[ "$ready" != "true" ]]; then
        echo "FAIL (server not ready)"
        cat "$server_out" | sed 's/^/    /'
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        rm -f "$server_out"
        FAIL=$((FAIL + 1))
        return
    fi

    local acceptor_addr handshake_addr client_out
    acceptor_addr=$(grep 'ACCEPTOR=' "$server_out" | head -1 | cut -d= -f2)
    handshake_addr=$(grep 'HANDSHAKE=' "$server_out" | head -1 | cut -d= -f2)
    client_out=$(mktemp)

    if timeout "$TIMEOUT" "$client_bin" client \
        --protocol "$protocol" \
        --addr "$acceptor_addr" \
        --handshake-addr "$handshake_addr" \
        --scenario "$scenario" > "$client_out" 2>&1 \
        && grep -q "SUCCESS" "$client_out"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "  Client output:"
        cat "$client_out" | sed 's/^/    /'
        echo "  Server output:"
        cat "$server_out" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -f "$server_out" "$client_out"
}

# -- Run all tests --

echo ""
echo "=== Cross-version compatibility tests ==="

for protocol in tcp udp; do
    for scenario in echo large-echo bidirectional; do
        run_test "$CURRENT"  "$PREVIOUS" "new-server + old-client" "$protocol" "$scenario"
        run_test "$PREVIOUS" "$CURRENT"  "old-server + new-client" "$protocol" "$scenario"
    done
done

echo ""
echo "--- Sanity ---"
run_test "$CURRENT" "$CURRENT" "self-talk" tcp echo

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
