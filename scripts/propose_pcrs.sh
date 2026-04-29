#!/bin/bash
# propose_pcrs.sh — Propose PCR values to the dev or prod Safe multisig.
#
# Prerequisites:
#   - cast (Foundry) for ABI encoding and signing
#   - python3 and jq for JSON manipulation
#
# Usage:
#   MANIFEST_JSON=<path> PROPOSER_PRIVATE_KEY=0x... ./scripts/propose_pcrs.sh <env>
#
# Environments:
#   sepolia-dev   → Sepolia Safe + Sepolia dev   ImageAllowlist
#   sepolia-prod  → Sepolia Safe + Sepolia prod  ImageAllowlist (same Safe as sepolia-dev)
#   mainnet-prod  → Mainnet Safe + Mainnet prod  ImageAllowlist
#
# A real release proposes to all three.
#
# Manifest source (required):
#   MANIFEST_JSON=<path>  — full build attestation manifest (the JSON written to
#                           gs://$PROVENANCE_BUCKET/<image>/attestation.json).
#                           Use '-' or /dev/stdin to read piped input.
#
# IMAGE_VERSION and IMAGE_DESCRIPTION are derived from .output.name in the
# manifest (e.g. "cs-image-0-1-2-hardened" → version "0.1.2"). Both can be
# overridden via env vars if needed.
#
# Pipe directly from GCS:
#   gsutil cat gs://$PROVENANCE_BUCKET/<image>/attestation.json \
#     | MANIFEST_JSON=- PROPOSER_PRIVATE_KEY=0x... \
#       ./scripts/propose_pcrs.sh prod
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

fail() { echo "error: $*" >&2; exit 1; }

ENVIRONMENT="${1:-}"
case "$ENVIRONMENT" in
  sepolia-dev)
    SAFE_ADDRESS="${SAFE_ADDRESS:-0xb094Ba769b4976Dc37fC689A76675f31bc4923b0}"
    IMAGE_ALLOWLIST_ADDRESS="${IMAGE_ALLOWLIST_ADDRESS:-0x6B6Ce40D81Ae3C261B217D001A07a5b268FFE86e}"
    RPC_URL="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
    SAFE_NETWORK="${SAFE_NETWORK:-sep}"
    ;;
  sepolia-prod)
    SAFE_ADDRESS="${SAFE_ADDRESS:-0xb094Ba769b4976Dc37fC689A76675f31bc4923b0}"
    IMAGE_ALLOWLIST_ADDRESS="${IMAGE_ALLOWLIST_ADDRESS:-0x7c66A1e862E11C4887270aBd649157ACe837A2D0}"
    RPC_URL="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
    SAFE_NETWORK="${SAFE_NETWORK:-sep}"
    ;;
  mainnet-prod)
    SAFE_ADDRESS="${SAFE_ADDRESS:-0x684cf8978c2815716c85eAa237E311f5a44e9e09}"
    IMAGE_ALLOWLIST_ADDRESS="${IMAGE_ALLOWLIST_ADDRESS:-0xb4713c7Cf195fAE4C9947a6Fe069740df6004d72}"
    RPC_URL="${RPC_URL:-https://ethereum-rpc.publicnode.com}"
    SAFE_NETWORK="${SAFE_NETWORK:-eth}"
    ;;
  *)
    fail "Usage: $0 <sepolia-dev|sepolia-prod|mainnet-prod>"
    ;;
esac

PROPOSER_PRIVATE_KEY="${PROPOSER_PRIVATE_KEY:-}"
[[ -n "$PROPOSER_PRIVATE_KEY" ]] || fail "PROPOSER_PRIVATE_KEY is required"

command -v cast    >/dev/null || fail "cast (Foundry) not found"
command -v python3 >/dev/null || fail "python3 not found"
command -v jq      >/dev/null || fail "jq not found"

PROPOSER_ADDRESS="${PROPOSER_ADDRESS:-$(cast wallet address --private-key "$PROPOSER_PRIVATE_KEY")}"
MULTISEND_ADDRESS="${MULTISEND_ADDRESS:-0x40A2aCCbd92BCA938b02010E17A5b8929b49130D}"

# =============================================================================
# Read manifest (PCRs + image identity)
# =============================================================================

MANIFEST_JSON="${MANIFEST_JSON:-}"
[[ -n "$MANIFEST_JSON" ]] || fail "MANIFEST_JSON is required (path to attestation manifest JSON, or '-' for stdin)"

if [[ "$MANIFEST_JSON" == "-" ]]; then
  MANIFEST_JSON=/dev/stdin
fi
[[ -r "$MANIFEST_JSON" ]] || fail "MANIFEST_JSON not readable: ${MANIFEST_JSON}"

# Slurp once so we can read /dev/stdin without consuming it many times.
MANIFEST_DATA=$(cat "$MANIFEST_JSON")

# Validate all required paths up-front. `fail` from inside $(...) only exits
# the subshell, so we check before assigning instead of inside command
# substitution.
for path in .output.name \
            .pcrs.intel_tdx.pcr4 .pcrs.intel_tdx.pcr8 .pcrs.intel_tdx.pcr9 \
            .pcrs.amd_sev_snp.pcr4 .pcrs.amd_sev_snp.pcr8 .pcrs.amd_sev_snp.pcr9 \
            .pcrs.gcp_shielded_vm.pcr4 .pcrs.gcp_shielded_vm.pcr8 .pcrs.gcp_shielded_vm.pcr9; do
  jq -e "$path" <<<"$MANIFEST_DATA" >/dev/null \
    || fail "missing or null field at ${path} in MANIFEST_JSON"
done

OUTPUT_NAME=$(jq -r '.output.name' <<<"$MANIFEST_DATA")

# Derive version from .output.name. Expected shape: cs-image-X-Y-Z-{debug|hardened}
# e.g. "cs-image-0-1-2-hardened" → "0.1.2".
# `sed -n .../p` only emits a line when the regex matches, so a non-matching
# input produces an empty string instead of silently passing through.
DERIVED_DASHES=$(echo "$OUTPUT_NAME" \
  | sed -En 's/^cs-image-([0-9]+-[0-9]+-[0-9]+)-(debug|hardened)$/\1/p')
[[ -n "$DERIVED_DASHES" ]] \
  || fail "could not derive version from .output.name='${OUTPUT_NAME}' (expected cs-image-X-Y-Z-{debug|hardened})"
DERIVED_VERSION=$(echo "$DERIVED_DASHES" | tr '-' '.')

IMAGE_VERSION="${IMAGE_VERSION:-$DERIVED_VERSION}"
IMAGE_DESCRIPTION="${IMAGE_DESCRIPTION:-$OUTPUT_NAME}"

TDX_PCR4=$(jq -r '.pcrs.intel_tdx.pcr4'       <<<"$MANIFEST_DATA")
TDX_PCR8=$(jq -r '.pcrs.intel_tdx.pcr8'       <<<"$MANIFEST_DATA")
TDX_PCR9=$(jq -r '.pcrs.intel_tdx.pcr9'       <<<"$MANIFEST_DATA")
SEV_PCR4=$(jq -r '.pcrs.amd_sev_snp.pcr4'     <<<"$MANIFEST_DATA")
SEV_PCR8=$(jq -r '.pcrs.amd_sev_snp.pcr8'     <<<"$MANIFEST_DATA")
SEV_PCR9=$(jq -r '.pcrs.amd_sev_snp.pcr9'     <<<"$MANIFEST_DATA")
SVM_PCR4=$(jq -r '.pcrs.gcp_shielded_vm.pcr4' <<<"$MANIFEST_DATA")
SVM_PCR8=$(jq -r '.pcrs.gcp_shielded_vm.pcr8' <<<"$MANIFEST_DATA")
SVM_PCR9=$(jq -r '.pcrs.gcp_shielded_vm.pcr9' <<<"$MANIFEST_DATA")

echo "=== Propose PCRs to Safe ==="
echo "  Environment: ${ENVIRONMENT} (chain=${SAFE_NETWORK})"
echo "  Safe:       ${SAFE_ADDRESS}"
echo "  Allowlist:  ${IMAGE_ALLOWLIST_ADDRESS}"
echo "  Manifest:   ${MANIFEST_JSON}"
echo "  Image:      ${OUTPUT_NAME}"
echo "  Version:    ${IMAGE_VERSION}"
echo "  Proposer:   ${PROPOSER_ADDRESS}"
echo ""

# =============================================================================
# Encode calldata
# =============================================================================

pad_bytes32() {
  local hex="$1"
  hex="${hex#0x}"
  printf -v padded "%-64s" "$hex"
  echo "0x${padded// /0}"
}

encode_add_images() {
  local platform_id="$1"
  local pcr4_hex="$2"
  local pcr8_hex="$3"
  local pcr9_hex="$4"
  local version="$5"
  local description="$6"

  local pcr4_padded pcr8_padded pcr9_padded
  pcr4_padded=$(pad_bytes32 "$pcr4_hex")
  pcr8_padded=$(pad_bytes32 "$pcr8_hex")
  pcr9_padded=$(pad_bytes32 "$pcr9_hex")

  cast calldata \
    "addImages(uint8,((uint8,bytes32)[],string,string)[])" \
    "$platform_id" \
    "[([(4,${pcr4_padded}),(8,${pcr8_padded}),(9,${pcr9_padded})],\"${version}\",\"${description}\")]"
}

echo "encoding addImages calldata for each platform..."

# Platform IDs: TDX=0, SEV_SNP=1, Shielded=2
CALLDATA_TDX=$(encode_add_images 0 "$TDX_PCR4" "$TDX_PCR8" "$TDX_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")
CALLDATA_SEV=$(encode_add_images 1 "$SEV_PCR4" "$SEV_PCR8" "$SEV_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")
CALLDATA_SVM=$(encode_add_images 2 "$SVM_PCR4" "$SVM_PCR8" "$SVM_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")

# =============================================================================
# Pack MultiSend transactions
# =============================================================================

pack_multisend_tx() {
  local to="$1"
  local calldata="$2"

  local data_hex="${calldata#0x}"
  local data_len=$(( ${#data_hex} / 2 ))

  local to_hex="${to#0x}"
  to_hex=$(echo "$to_hex" | tr '[:upper:]' '[:lower:]')
  local value_hex
  value_hex=$(printf '%064d' 0)
  local len_hex
  len_hex=$(printf '%064x' "$data_len")

  echo "00${to_hex}${value_hex}${len_hex}${data_hex}"
}

echo "packing MultiSend transactions..."

TX_TDX=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_TDX")
TX_SEV=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_SEV")
TX_SVM=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_SVM")

PACKED_TXS="${TX_TDX}${TX_SEV}${TX_SVM}"
MULTISEND_CALLDATA=$(cast calldata "multiSend(bytes)" "0x${PACKED_TXS}")

# =============================================================================
# Sign & propose to Safe
# =============================================================================

echo "getting Safe nonce..."

SAFE_NONCE=$(cast call "$SAFE_ADDRESS" "nonce()(uint256)" --rpc-url "$RPC_URL")
echo "  nonce: ${SAFE_NONCE}"

echo "computing safeTxHash on-chain..."

SAFE_TX_HASH=$(cast call "$SAFE_ADDRESS" \
  "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)(bytes32)" \
  "$MULTISEND_ADDRESS" \
  0 \
  "$MULTISEND_CALLDATA" \
  1 \
  0 \
  0 \
  0 \
  "0x0000000000000000000000000000000000000000" \
  "0x0000000000000000000000000000000000000000" \
  "$SAFE_NONCE" \
  --rpc-url "$RPC_URL")

echo "  safeTxHash: ${SAFE_TX_HASH}"

echo "signing transaction..."

SIGNATURE=$(cast wallet sign --no-hash "$SAFE_TX_HASH" --private-key "$PROPOSER_PRIVATE_KEY")
echo "  signature: ${SIGNATURE}"

echo "posting transaction to Safe Transaction Service..."

PAYLOAD=$(python3 -c "
import json, sys

payload = {
    'to': sys.argv[1],
    'value': '0',
    'data': sys.argv[2],
    'operation': 1,
    'safeTxGas': '0',
    'baseGas': '0',
    'gasPrice': '0',
    'gasToken': '0x0000000000000000000000000000000000000000',
    'refundReceiver': '0x0000000000000000000000000000000000000000',
    'nonce': int(sys.argv[3]),
    'contractTransactionHash': sys.argv[4],
    'sender': sys.argv[5],
    'signature': sys.argv[6],
}
print(json.dumps(payload))
" "$MULTISEND_ADDRESS" "$MULTISEND_CALLDATA" "$SAFE_NONCE" "$SAFE_TX_HASH" "$PROPOSER_ADDRESS" "$SIGNATURE")

SAFE_API_URL="https://api.safe.global/tx-service/${SAFE_NETWORK}/api/v1/safes/${SAFE_ADDRESS}/multisig-transactions/"

RESPONSE_BODY=$(mktemp)
HTTP_STATUS=$(curl -s \
  -o "$RESPONSE_BODY" -w "%{http_code}" \
  -X POST "$SAFE_API_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -lt 300 ]]; then
  echo "transaction proposed successfully (HTTP ${HTTP_STATUS})"
else
  echo "warning: Safe API returned HTTP ${HTTP_STATUS}" >&2
  cat "$RESPONSE_BODY" >&2
  echo "" >&2
fi
rm -f "$RESPONSE_BODY"

# =============================================================================
# Summary
# =============================================================================

SAFE_TX_HASH_SHORT="${SAFE_TX_HASH#0x}"
SAFE_APP_URL="https://app.safe.global/transactions/tx?safe=${SAFE_NETWORK}:${SAFE_ADDRESS}&id=multisig_${SAFE_ADDRESS}_0x${SAFE_TX_HASH_SHORT}"

echo ""
echo "=== Summary ==="
echo "  Version:       ${IMAGE_VERSION}"
echo "  Safe tx hash:  ${SAFE_TX_HASH}"
echo ""
echo "  Approve in Safe:"
echo "  ${SAFE_APP_URL}"
echo ""
echo "Done."
