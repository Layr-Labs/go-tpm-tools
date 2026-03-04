#!/bin/bash
# deploy_to_dev.sh — Capture PCRs, promote image to dev, propose on-chain allowlist via Safe.
#
# This script is for hardened images only. Debug images are not supported.
#
# Three phases:
#   1. PCR Capture: Boot VMs on TDX/SEV-SNP/Shielded, collect PCR values via GCS
#   2. Image Promotion: Copy image to dev family, grant IAM access to dev project
#   3. On-Chain Proposal: Encode addImages calldata, propose via Safe multisig
#
# Prerequisites:
#   - gcloud CLI authenticated
#   - cast (Foundry) for ABI encoding and signing
#   - python3 and jq for JSON manipulation
#
# Usage:
#   IMAGE_NAME=eigen-compute-hardened-test-1234 \
#   PROPOSER_PRIVATE_KEY=0x... \
#   ./scripts/deploy_to_dev.sh
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

fail() { echo "error: $*" >&2; exit 1; }

# Required
IMAGE_NAME="${IMAGE_NAME:-}"
PROPOSER_PRIVATE_KEY="${PROPOSER_PRIVATE_KEY:-}"

[[ -n "$IMAGE_NAME" ]]          || fail "IMAGE_NAME is required"
[[ -n "$PROPOSER_PRIVATE_KEY" ]] || fail "PROPOSER_PRIVATE_KEY is required"

command -v gcloud  >/dev/null || fail "gcloud CLI not found"
command -v cast    >/dev/null || fail "cast (Foundry) not found"
command -v python3 >/dev/null || fail "python3 not found"
command -v jq      >/dev/null || fail "jq not found"

# Derived defaults
# BUILD_PROJECT: scratch project for building images and capturing PCRs
BUILD_PROJECT="${BUILD_PROJECT:-data-axiom-440223-j1}"
# GLOBAL_IMAGE_PROJECT: central registry where promoted images are published
GLOBAL_IMAGE_PROJECT="${GLOBAL_IMAGE_PROJECT:-tee-compute-global}"
# DEV_PROJECT: the dev environment that gets IAM access to promoted images
DEV_PROJECT="${DEV_PROJECT:-tee-compute-sepolia-dev}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PCR_CAPTURE_IMAGE="${PCR_CAPTURE_IMAGE:-us-central1-docker.pkg.dev/tee-compute-global/cs-build/pcr-capture:v0.1.0-test.0}"
SAFE_ADDRESS="${SAFE_ADDRESS:-0xb094Ba769b4976Dc37fC689A76675f31bc4923b0}"
PROPOSER_ADDRESS="${PROPOSER_ADDRESS:-$(cast wallet address --private-key "$PROPOSER_PRIVATE_KEY")}"
IMAGE_VERSION="${IMAGE_VERSION:-$(git -C "$REPO_ROOT" rev-parse --short HEAD)}"
IMAGE_DESCRIPTION="${IMAGE_DESCRIPTION:-${IMAGE_NAME}}"

# Optional overrides
TDX_ZONE="${TDX_ZONE:-us-central1-a}"
SEV_ZONE="${SEV_ZONE:-us-central1-a}"
SVM_ZONE="${SVM_ZONE:-us-central1-a}"
GCS_BUCKET="${GCS_BUCKET:-${BUILD_PROJECT}_cloudbuild}"
# The instance-creator SA in the dev project is what actually calls the GCE API to create TEE VMs.
INSTANCE_CREATOR_SA="${INSTANCE_CREATOR_SA:-instance-creator-sepolia-dev@tee-compute-sepolia-dev.iam.gserviceaccount.com}"
IMAGE_ALLOWLIST_ADDRESS="${IMAGE_ALLOWLIST_ADDRESS:-0x6B6Ce40D81Ae3C261B217D001A07a5b268FFE86e}"
MULTISEND_ADDRESS="${MULTISEND_ADDRESS:-0x40A2aCCbd92BCA938b02010E17A5b8929b49130D}"
SEPOLIA_RPC_URL="${SEPOLIA_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"

TIMESTAMP=$(date +%s)
GCS_PREFIX="gs://${GCS_BUCKET}/pcr-capture"
PCR_OUTPUT="${SCRIPT_DIR}/pcrs.json"

echo "=== Deploy to Dev ==="
echo "  Image:        ${IMAGE_NAME} (hardened)"
echo "  Build project: ${BUILD_PROJECT}"
echo "  Image project: ${GLOBAL_IMAGE_PROJECT}"
echo "  Dev project:   ${DEV_PROJECT}"
echo "  Version:       ${IMAGE_VERSION}"
echo "  Proposer:      ${PROPOSER_ADDRESS}"
echo ""

# =============================================================================
# VM Tracking & Cleanup
# =============================================================================

CREATED_VMS=()

cleanup() {
  echo ""
  echo "=== Cleaning up VMs ==="
  if [[ ${#CREATED_VMS[@]} -gt 0 ]]; then
    for vm_spec in "${CREATED_VMS[@]}"; do
      IFS='|' read -r name zone <<< "$vm_spec"
      echo "deleting ${name} in ${zone}..."
      gcloud compute instances delete "$name" --zone="$zone" --project="$BUILD_PROJECT" --quiet 2>/dev/null || true
    done
  fi
}
trap cleanup EXIT

# =============================================================================
# Phase 1: PCR Capture
# =============================================================================

create_capture_vm() {
  local name="$1"
  local zone="$2"
  local machine_type="$3"
  shift 3
  # Remaining args are extra gcloud flags (e.g. --confidential-compute-type=TDX).

  local gcs_path="${GCS_PREFIX}/${name}.json"
  echo "creating VM: ${name} (${machine_type} in ${zone}), GCS output: ${gcs_path}"

  gcloud compute instances create "$name" \
    --project="$BUILD_PROJECT" \
    --zone="$zone" \
    --machine-type="$machine_type" \
    --scopes=cloud-platform \
    --image="$IMAGE_NAME" \
    --image-project="$BUILD_PROJECT" \
    --metadata="tee-image-reference=${PCR_CAPTURE_IMAGE},tee-restart-policy=Never,tee-container-log-redirect=true,tee-env-GCS_OUTPUT=${gcs_path},self-verification=true" \
    --boot-disk-size=30GB \
    --shielded-secure-boot \
    "$@"

  CREATED_VMS+=("${name}|${zone}")
}

poll_gcs() {
  local name="$1"
  local zone="$2"
  local gcs_path="${GCS_PREFIX}/${name}.json"
  local timeout_secs=600
  local start=$SECONDS

  echo "polling GCS for ${name} at ${gcs_path}..." >&2

  while (( SECONDS - start < timeout_secs )); do
    local tmpfile
    tmpfile=$(mktemp)

    if gcloud storage cat "$gcs_path" > "$tmpfile" 2>/dev/null; then
      if python3 -c 'import json,sys; json.load(sys.stdin)' < "$tmpfile" 2>/dev/null; then
        cat "$tmpfile"
        rm -f "$tmpfile"
        return 0
      fi
    fi
    rm -f "$tmpfile"

    # Check if VM stopped unexpectedly.
    local status
    status=$(gcloud compute instances describe "$name" --zone="$zone" \
      --project="$BUILD_PROJECT" --format="value(status)" 2>/dev/null || echo "UNKNOWN")
    if [[ "$status" == "TERMINATED" || "$status" == "STOPPED" ]]; then
      echo "error: VM ${name} stopped before producing PCR output" >&2
      return 1
    fi

    sleep 15
  done

  echo "error: timed out waiting for PCR output from ${name}" >&2
  return 1
}

echo "=== Phase 1: PCR Capture ==="

VM_TDX="pcr-cap-tdx-${TIMESTAMP}"
VM_SEV="pcr-cap-sev-${TIMESTAMP}"
VM_SVM="pcr-cap-svm-${TIMESTAMP}"

create_capture_vm "$VM_TDX" "$TDX_ZONE" "c3-standard-4" \
  --maintenance-policy=TERMINATE --confidential-compute-type=TDX --min-cpu-platform="Intel Sapphire Rapids"
create_capture_vm "$VM_SEV" "$SEV_ZONE" "n2d-standard-2" \
  --maintenance-policy=TERMINATE --confidential-compute-type=SEV_SNP
create_capture_vm "$VM_SVM" "$SVM_ZONE" "e2-medium"

echo ""
echo "=== Fetching PCR values via GCS ==="

# Fetch all three in parallel.
TMP_TDX=$(mktemp)
TMP_SEV=$(mktemp)
TMP_SVM=$(mktemp)

poll_gcs "$VM_TDX" "$TDX_ZONE" > "$TMP_TDX" &
PID_TDX=$!
poll_gcs "$VM_SEV" "$SEV_ZONE" > "$TMP_SEV" &
PID_SEV=$!
poll_gcs "$VM_SVM" "$SVM_ZONE" > "$TMP_SVM" &
PID_SVM=$!

FAIL=0
wait "$PID_TDX" || { echo "error: TDX PCR capture failed" >&2; FAIL=1; }
wait "$PID_SEV" || { echo "error: SEV-SNP PCR capture failed" >&2; FAIL=1; }
wait "$PID_SVM" || { echo "error: Shielded VM PCR capture failed" >&2; FAIL=1; }

if [[ "$FAIL" -ne 0 ]]; then
  rm -f "$TMP_TDX" "$TMP_SEV" "$TMP_SVM"
  fail "PCR capture failed for one or more platforms"
fi

# Merge into a single JSON keyed by platform.
# Each per-platform file has: {"platform": "...", "pcrs": {"4": "hex", "8": "hex", "9": "hex"}}
python3 -c "
import json, sys

platforms = {}
for label, path in [('intel_tdx', sys.argv[1]), ('amd_sev_snp', sys.argv[2]), ('gcp_shielded_vm', sys.argv[3])]:
    with open(path) as f:
        data = json.load(f)
    pcrs = data.get('pcrs', data)
    platforms[label] = {
        'pcr4': pcrs.get('4', pcrs.get('pcr4', '')),
        'pcr8': pcrs.get('8', pcrs.get('pcr8', '')),
        'pcr9': pcrs.get('9', pcrs.get('pcr9', '')),
    }

print(json.dumps(platforms, indent=2))
" "$TMP_TDX" "$TMP_SEV" "$TMP_SVM" > "$PCR_OUTPUT"

rm -f "$TMP_TDX" "$TMP_SEV" "$TMP_SVM"

echo "PCR values written to ${PCR_OUTPUT}"
echo ""
jq . "$PCR_OUTPUT"
echo ""

# =============================================================================
# Phase 2: Image Promotion
# =============================================================================

echo "=== Phase 2: Image Promotion ==="

DEV_IMAGE_NAME="${IMAGE_NAME}-preview"
DEV_FAMILY="cs-image-hardened-dev"

echo "creating dev copy: ${DEV_IMAGE_NAME} in family ${DEV_FAMILY} (project: ${GLOBAL_IMAGE_PROJECT})"

gcloud compute images create "$DEV_IMAGE_NAME" \
  --source-image="$IMAGE_NAME" \
  --source-image-project="$BUILD_PROJECT" \
  --family="$DEV_FAMILY" \
  --project="$GLOBAL_IMAGE_PROJECT"

# Grant the instance-creator SA access to use the dev image.
echo "granting ${INSTANCE_CREATOR_SA} access to ${DEV_IMAGE_NAME}..."
gcloud compute images add-iam-policy-binding "$DEV_IMAGE_NAME" \
  --member="serviceAccount:${INSTANCE_CREATOR_SA}" \
  --role=roles/compute.imageUser \
  --project="$GLOBAL_IMAGE_PROJECT"

echo "image promoted to dev"
echo ""

# =============================================================================
# Phase 3: On-Chain Proposal via Safe
# =============================================================================

echo "=== Phase 3: On-Chain Proposal ==="

# Helper: zero-pad a hex PCR value to 32 bytes (64 hex chars).
pad_bytes32() {
  local hex="$1"
  # Strip 0x prefix if present.
  hex="${hex#0x}"
  # Pad to 64 hex chars (32 bytes).
  printf -v padded "%-64s" "$hex"
  echo "0x${padded// /0}"
}

# Encode addImages calldata for a single platform.
# addImages(uint8 platform, (uint8 pcrIndex, bytes32 pcrValue)[] pcrs, string version, string description)
# Solidity: addImages(uint8,((uint8,bytes32)[],string,string)[])
#   platform enum: TDX=0, SEV_SNP=1, Shielded=2
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

  # Encode the calldata using cast.
  # addImages(uint8,((uint8,bytes32)[],string,string)[])
  # The Image struct is: ((uint8,bytes32)[] pcrs, string version, string description)
  # We pass a single Image in the array.
  cast calldata \
    "addImages(uint8,((uint8,bytes32)[],string,string)[])" \
    "$platform_id" \
    "[([(4,${pcr4_padded}),(8,${pcr8_padded}),(9,${pcr9_padded})],\"${version}\",\"${description}\")]"
}

# Read PCR values from the merged JSON.
TDX_PCR4=$(jq -r '.intel_tdx.pcr4' "$PCR_OUTPUT")
TDX_PCR8=$(jq -r '.intel_tdx.pcr8' "$PCR_OUTPUT")
TDX_PCR9=$(jq -r '.intel_tdx.pcr9' "$PCR_OUTPUT")

SEV_PCR4=$(jq -r '.amd_sev_snp.pcr4' "$PCR_OUTPUT")
SEV_PCR8=$(jq -r '.amd_sev_snp.pcr8' "$PCR_OUTPUT")
SEV_PCR9=$(jq -r '.amd_sev_snp.pcr9' "$PCR_OUTPUT")

SVM_PCR4=$(jq -r '.gcp_shielded_vm.pcr4' "$PCR_OUTPUT")
SVM_PCR8=$(jq -r '.gcp_shielded_vm.pcr8' "$PCR_OUTPUT")
SVM_PCR9=$(jq -r '.gcp_shielded_vm.pcr9' "$PCR_OUTPUT")

echo "encoding addImages calldata for each platform..."

# Platform IDs: TDX=0, SEV_SNP=1, Shielded=2
CALLDATA_TDX=$(encode_add_images 0 "$TDX_PCR4" "$TDX_PCR8" "$TDX_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")
CALLDATA_SEV=$(encode_add_images 1 "$SEV_PCR4" "$SEV_PCR8" "$SEV_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")
CALLDATA_SVM=$(encode_add_images 2 "$SVM_PCR4" "$SVM_PCR8" "$SVM_PCR9" "$IMAGE_VERSION" "$IMAGE_DESCRIPTION")

# Pack MultiSend transactions.
# Each sub-tx: operation(1 byte, 0=Call) + to(20 bytes) + value(32 bytes) + dataLength(32 bytes) + data
pack_multisend_tx() {
  local to="$1"
  local calldata="$2"

  # Strip 0x prefix from calldata.
  local data_hex="${calldata#0x}"
  local data_len=$(( ${#data_hex} / 2 ))

  # operation: 00 (Call)
  # to: 20 bytes (strip 0x, lowercase)
  local to_hex="${to#0x}"
  to_hex=$(echo "$to_hex" | tr '[:upper:]' '[:lower:]')
  # value: 32 bytes of zeros
  local value_hex
  value_hex=$(printf '%064d' 0)
  # dataLength: 32 bytes
  local len_hex
  len_hex=$(printf '%064x' "$data_len")

  echo "00${to_hex}${value_hex}${len_hex}${data_hex}"
}

echo "packing MultiSend transactions..."

TX_TDX=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_TDX")
TX_SEV=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_SEV")
TX_SVM=$(pack_multisend_tx "$IMAGE_ALLOWLIST_ADDRESS" "$CALLDATA_SVM")

# Concatenate all packed transactions.
PACKED_TXS="${TX_TDX}${TX_SEV}${TX_SVM}"

# Encode multiSend(bytes) calldata targeting MultiSendCallOnly.
MULTISEND_CALLDATA=$(cast calldata "multiSend(bytes)" "0x${PACKED_TXS}")

echo "getting Safe nonce..."

SAFE_NONCE=$(cast call "$SAFE_ADDRESS" "nonce()(uint256)" --rpc-url "$SEPOLIA_RPC_URL")

echo "  nonce: ${SAFE_NONCE}"

echo "computing safeTxHash on-chain..."

# getTransactionHash(address to, uint256 value, bytes data, uint8 operation,
#   uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
#   address gasToken, address refundReceiver, uint256 _nonce) → bytes32
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
  --rpc-url "$SEPOLIA_RPC_URL")

echo "  safeTxHash: ${SAFE_TX_HASH}"

echo "signing transaction..."

SIGNATURE=$(cast wallet sign --no-hash "$SAFE_TX_HASH" --private-key "$PROPOSER_PRIVATE_KEY")

echo "  signature: ${SIGNATURE}"

echo "posting transaction to Safe Transaction Service..."

# Build the JSON payload for the Safe Transaction Service.
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

SAFE_API_URL="https://api.safe.global/tx-service/sep/api/v1/safes/${SAFE_ADDRESS}/multisig-transactions/"

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
SAFE_APP_URL="https://app.safe.global/transactions/tx?safe=sep:${SAFE_ADDRESS}&id=multisig_${SAFE_ADDRESS}_0x${SAFE_TX_HASH_SHORT}"

echo ""
echo "=== Summary ==="
echo "  Image:         ${IMAGE_NAME}"
echo "  Dev copy:      ${DEV_IMAGE_NAME}"
echo "  Dev family:    ${DEV_FAMILY}"
echo "  PCR output:    ${PCR_OUTPUT}"
echo "  Safe tx hash:  ${SAFE_TX_HASH}"
echo ""
echo "  Approve in Safe:"
echo "  ${SAFE_APP_URL}"
echo ""
echo "Done."
