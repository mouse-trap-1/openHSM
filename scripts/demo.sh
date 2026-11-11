#!/usr/bin/env bash
# End-to-end demonstration of the OpenHSM prototype on one machine.
#
# Every node is two processes, as on the real board: `openhsm-hwsim` models
# the tamper enclosure (signing module + tamper supervisor) and `openhsmd` is
# the SoC. The demo builds a cluster with three admins (quorum 2), creates an
# Ethereum and a Bitcoin wallet, signs transactions under policy, shows policy
# denials, splits the KEK onto operator cards, enrols a second node over
# ECIES, trips a tamper sensor, recovers on a fresh node from operator cards,
# rotates the KEK and verifies the audit log.
#
# Usage: scripts/demo.sh [workdir]        (needs: cargo, python3)
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet
BIN="$PWD/target/release"
W="${1:-$(mktemp -d)}"
mkdir -p "$W"
PORT_A=${PORT_A:-7443}
PORT_B=${PORT_B:-7444}
PORT_C=${PORT_C:-7445}
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 did not open" >&2; return 1; }

# quorum NODE_PROFILE METHOD PARAMS : alice proposes, bob approves, alice submits.
quorum() {
  local profile="$1" method="$2" params="${3:-{\}}" op node
  node="${profile##*@}"; node="${node%.json}"
  op="$W/op-$(date +%s%N).json"
  "$BIN/hsmctl" propose --cluster demo --node "$node" --out "$op" "$method" "$params" >/dev/null
  "$BIN/hsmctl" approve --id bob --sign-key "$W/ids/bob.sign" "$op" >/dev/null 2>&1
  "$BIN/hsmctl" submit --profile "$profile" "$op"
}

declare -A NODE_PID
sim() { "$BIN/hsmctl" sim --socket "$W/$1.phys" "${@:2}" | sed 's/^/   [physical] /'; }

start_node() { # NAME PORT
  "$BIN/openhsm-hwsim" provision --state "$W/$1.enclosure" | sed 's/^/   /'
  "$BIN/openhsm-hwsim" run --state "$W/$1.enclosure" --soc-socket "$W/$1.soc" --physical-socket "$W/$1.phys" 2>"$W/$1.hw.log" &
  PIDS+=($!)
  for _ in $(seq 100); do [ -S "$W/$1.soc" ] && [ -S "$W/$1.phys" ] && break; sleep 0.05; done
  "$BIN/openhsmd" init --data "$W/$1" --genesis "$W/genesis.json" --node-id "$1" --hardware "unix:$W/$1.soc" | sed 's/^/   /'
  "$BIN/hsmctl" pki sign-csr --ca-dir "$W/pki" --csr "$W/$1/tls/node.csr" --out "$W/$1/tls/node.crt" >/dev/null
  "$BIN/openhsmd" run --data "$W/$1" --listen "127.0.0.1:$2" --hardware "unix:$W/$1.soc" 2>"$W/$1.log" &
  NODE_PID[$1]=$!; PIDS+=($!)
  wait_port "$2"
  for who in alice bob app1 auditor1; do
    "$BIN/hsmctl" profile --addr "127.0.0.1:$2" --cluster demo --ca "$W/pki/ca.crt" --identity-dir "$W/ids" --name "$who" --out "$W/$who@$1.json"
  done
}

say "1. Operators create the CA, three admins, an application server and an auditor"
"$BIN/hsmctl" pki init --out "$W/pki"
for a in alice bob carol; do "$BIN/hsmctl" identity --ca-dir "$W/pki" --name "$a" --role admin --out "$W/ids" >/dev/null; done
"$BIN/hsmctl" identity --ca-dir "$W/pki" --name app1 --role signer --out "$W/ids" >/dev/null
"$BIN/hsmctl" identity --ca-dir "$W/pki" --name auditor1 --role auditor --out "$W/ids" >/dev/null
"$BIN/hsmctl" genesis --cluster demo --quorum 2 --lease-divisor 1 --ca "$W/pki/ca.crt" \
  --principal "$W/ids/alice.principal.json" --principal "$W/ids/bob.principal.json" --principal "$W/ids/carol.principal.json" \
  --principal "$W/ids/app1.principal.json" --principal "$W/ids/auditor1.principal.json" --out "$W/genesis.json"

say "2. Node A: provision the enclosure, generate identity and TLS keys, start"
start_node node-a "$PORT_A"
A="$W/alice@node-a.json"; APP="$W/app1@node-a.json"

say "3. Admin quorum (alice + bob) generates the cluster KEK inside the signing module"
quorum "$A" kek_generate

say "4. Create an Ethereum wallet (Sepolia) and a Bitcoin wallet (testnet) with policies"
DEST_ETH=0x3535353535353535353535353535353535353535
ETH=$(quorum "$A" wallet_create "{\"label\":\"treasury-eth\",\"chain\":\"ethereum\",\"policy\":{
  \"chain_ids\":[11155111],\"max_per_tx\":\"50000000000000000\",\"max_per_day\":\"200000000000000000\",
  \"max_fee\":\"2100000000000000\",\"allowlist\":[\"$DEST_ETH\"]}}")
echo "$ETH"; ETH_ID=$(echo "$ETH" | field "['id']")
DEST_BTC=tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
BTC=$(quorum "$A" wallet_create "{\"label\":\"treasury-btc\",\"chain\":\"bitcoin\",\"network\":\"testnet\",\"policy\":{
  \"max_per_tx\":\"100000\",\"max_per_day\":\"300000\",\"max_fee\":\"5000\",\"max_fee_rate\":50,\"allowlist\":[\"$DEST_BTC\"]}}")
echo "$BTC"; BTC_ID=$(echo "$BTC" | field "['id']"); BTC_ADDR=$(echo "$BTC" | field "['address']")

say "5. Application server signs an EIP-1559 transfer on Sepolia"
"$BIN/hsmctl" call --profile "$APP" eth_sign_transaction "{\"wallet\":\"$ETH_ID\",\"tx\":{
  \"chain_id\":11155111,\"nonce\":0,\"gas_limit\":21000,\"to\":\"$DEST_ETH\",\"value\":\"10000000000000000\",
  \"max_fee_per_gas\":\"30000000000\",\"max_priority_fee_per_gas\":\"1500000000\"}}"

say "6. Application server signs a Bitcoin testnet P2WPKH spend with change"
"$BIN/hsmctl" call --profile "$APP" btc_sign_transaction "{\"wallet\":\"$BTC_ID\",\"tx\":{
  \"inputs\":[{\"txid\":\"7b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f\",\"vout\":0,\"amount\":250000}],
  \"outputs\":[{\"address\":\"$DEST_BTC\",\"amount\":90000},{\"address\":\"$BTC_ADDR\",\"amount\":159000}]}}"

say "7. Policy denials: recipient not on the allow-list, then amount over the per-transaction cap"
"$BIN/hsmctl" call --profile "$APP" eth_sign_transaction "{\"wallet\":\"$ETH_ID\",\"tx\":{
  \"chain_id\":11155111,\"nonce\":1,\"gas_limit\":21000,\"to\":\"0x000000000000000000000000000000000000dEaD\",\"value\":\"1\",
  \"max_fee_per_gas\":\"30000000000\",\"max_priority_fee_per_gas\":\"1500000000\"}}" || true
"$BIN/hsmctl" call --profile "$APP" eth_sign_transaction "{\"wallet\":\"$ETH_ID\",\"tx\":{
  \"chain_id\":11155111,\"nonce\":1,\"gas_limit\":21000,\"to\":\"$DEST_ETH\",\"value\":\"60000000000000000\",
  \"max_fee_per_gas\":\"30000000000\",\"max_priority_fee_per_gas\":\"1500000000\"}}" || true

say "8. Split the KEK 3-of-5 onto operator cards (software cards stand in for YubiKeys)"
for i in 1 2 3 4 5; do "$BIN/hsmctl" card-new --out "$W/node-a/cardslot/op$i.card" >/dev/null; done
echo "   with the ceremony key-switch off, even the quorum cannot move the KEK:"
quorum "$A" ceremony_split '{"m":3,"cards":["op1","op2","op3","op4","op5"]}' 2>&1 | sed 's/^/   /' || true
sim node-a ceremony on
quorum "$A" ceremony_split '{"m":3,"cards":["op1","op2","op3","op4","op5"]}' | field "['fp']" | sed 's/^/   KEK fingerprint in share headers: /'

say "9. Enrol node B: ECIES transfer of the KEK, authorised by the quorum, then replicate wallets"
start_node node-b "$PORT_B"
B="$W/alice@node-b.json"
ENROL=$("$BIN/hsmctl" call --profile "$B" enrol_begin)
EX=$(echo "$ENROL" | field "['enrol_x']"); EY=$(echo "$ENROL" | field "['enrol_y']")
quorum "$A" kek_export "{\"enrol_x\":\"$EX\",\"enrol_y\":\"$EY\",\"node\":\"node-b\"}" > "$W/kek-transfer.json"
sim node-a ceremony off
sim node-b ceremony on
"$BIN/hsmctl" call --profile "$B" kek_import "@$W/kek-transfer.json"
sim node-b ceremony off
"$BIN/hsmctl" call --profile "$A" snapshot_export > "$W/snapshot.json"
python3 -c "import json;print(json.dumps({'snapshot':json.load(open('$W/snapshot.json'))}))" > "$W/snapshot-import.json"
quorum "$B" snapshot_import "@$W/snapshot-import.json"
echo "   fingerprints: A=$("$BIN/hsmctl" call --profile "$A" kek_fingerprint | field "['fingerprint'][:16]") B=$("$BIN/hsmctl" call --profile "$B" kek_fingerprint | field "['fingerprint'][:16]")"
"$BIN/hsmctl" call --profile "$W/app1@node-b.json" eth_sign_transaction "{\"wallet\":\"$ETH_ID\",\"tx\":{
  \"chain_id\":11155111,\"nonce\":1,\"gas_limit\":21000,\"to\":\"$DEST_ETH\",\"value\":\"1000\",
  \"max_fee_per_gas\":\"30000000000\",\"max_priority_fee_per_gas\":\"1500000000\"}}" | field "['tx_hash']" | sed 's/^/   node B signed with the replicated wallet: /'

say "10. Tamper: the lid switch on node A opens"
sim node-a tamper lid
"$BIN/hsmctl" call --profile "$APP" status || true
kill "${NODE_PID[node-a]}" 2>/dev/null || true; sleep 0.3
"$BIN/openhsmd" run --data "$W/node-a" --listen "127.0.0.1:$PORT_A" --hardware "unix:$W/node-a.soc" 2>&1 | sed 's/^/   restart refused: /' || true

say "11. Break-glass: a fresh node C recovers the KEK from 3 of the 5 operator cards"
start_node node-c "$PORT_C"
C="$W/alice@node-c.json"
quorum "$C" snapshot_import "@$W/snapshot-import.json" >/dev/null
for i in 1 3 5; do cp "$W/node-a/cardslot/op$i.card" "$W/node-c/cardslot/"; done
sim node-c ceremony on
quorum "$C" ceremony_restore '{"cards":["op1","op3","op5"]}'
sim node-c ceremony off
"$BIN/hsmctl" call --profile "$W/app1@node-c.json" btc_sign_transaction "{\"wallet\":\"$BTC_ID\",\"tx\":{
  \"inputs\":[{\"txid\":\"7b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f\",\"vout\":1,\"amount\":50000}],
  \"outputs\":[{\"address\":\"$DEST_BTC\",\"amount\":49000}]}}" | field "['txid']" | sed 's/^/   node C signed after recovery, txid: /'

say "12. Rotate the KEK on node B, re-wrap every wallet, promote"
quorum "$B" rotate_begin >/dev/null
"$BIN/hsmctl" call --profile "$B" rotate_rewrap
quorum "$B" rotate_promote

say "13. Auditor verifies node B's audit log offline"
ID_B=$("$BIN/hsmctl" call --profile "$W/auditor1@node-b.json" audit_head | field "['identity']")
"$BIN/hsmctl" audit-verify --log "$W/node-b/audit.log" --identity "$ID_B"

say "Done. Work directory: $W"
