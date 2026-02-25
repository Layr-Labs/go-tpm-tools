#!/bin/bash
# capture_vectors.sh — Build the workload, run it on TDX / SEV-SNP / Shielded VMs
# for both debug and hardened images, and write test vectors to
# sdk/testdata/attestations.json.
#
# All VMs are created in parallel and vectors are fetched in parallel via GCS.
# The output file is overwritten completely (not merged).
#
# Prerequisites:
#   - gcloud CLI authenticated with a project that has Compute Engine
#   - Docker Hub account (docker login)
#   - Built debug and hardened Confidential Space images (e.g. from ./run_cloudbuild.sh)
#
# Usage:
#   DOCKER_USER=myuser \
#   CS_DEBUG_IMAGE=eigen-compute-debug-xxx \
#   CS_HARDENED_IMAGE=eigen-compute-hardened-xxx \
#   PROJECT=my-project \
#   ./capture_vectors.sh
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

# Docker Hub username — the workload image is pushed as docker.io/$DOCKER_USER/teeverify-capture:latest.
DOCKER_USER="${DOCKER_USER:-}"

# GCP project that owns the VMs.
PROJECT="${PROJECT:-my-project}"

# Confidential Space images. Provide both for full capture, or just one.
CS_DEBUG_IMAGE="${CS_DEBUG_IMAGE:-${CS_IMAGE_NAME:-}}"
CS_HARDENED_IMAGE="${CS_HARDENED_IMAGE:-}"
CS_IMAGE_PROJECT="${CS_IMAGE_PROJECT:-${PROJECT}}"

# Zones — pick zones that support each platform type.
TDX_ZONE="${TDX_ZONE:-us-central1-a}"
SEV_ZONE="${SEV_ZONE:-us-central1-a}"
SVM_ZONE="${SVM_ZONE:-us-central1-a}"

# =============================================================================
# Validation
# =============================================================================

if [[ -z "$DOCKER_USER" ]]; then
  echo "error: DOCKER_USER is required."
  echo "  e.g.: DOCKER_USER=myuser CS_DEBUG_IMAGE=... CS_HARDENED_IMAGE=... ./capture_vectors.sh"
  exit 1
fi

if [[ -z "$CS_DEBUG_IMAGE" && -z "$CS_HARDENED_IMAGE" ]]; then
  echo "error: at least one of CS_DEBUG_IMAGE or CS_HARDENED_IMAGE is required."
  echo "  e.g.: CS_DEBUG_IMAGE=eigen-compute-debug-xxx CS_HARDENED_IMAGE=eigen-compute-hardened-xxx ./capture_vectors.sh"
  exit 1
fi

WORKLOAD_IMAGE="docker.io/${DOCKER_USER}/teeverify-capture:latest"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUTPUT_FILE="${REPO_ROOT}/sdk/testdata/attestations.json"
TIMESTAMP=$(date +%s)

# GCS prefix for vector upload. Reuses the project's Cloud Build bucket.
GCS_PREFIX="gs://${PROJECT}_cloudbuild/teeverify-vectors"

# Track created VMs for cleanup.
CREATED_VMS=()

cleanup() {
  echo ""
  echo "=== Cleaning up ==="
  if [[ ${#CREATED_VMS[@]} -gt 0 ]]; then
    for vm_spec in "${CREATED_VMS[@]}"; do
      IFS='|' read -r name zone <<< "$vm_spec"
      echo "deleting ${name} in ${zone}..."
      gcloud compute instances delete "$name" --zone="$zone" --project="$PROJECT" --quiet 2>/dev/null || true
      # Clean up GCS vector file.
      gcloud storage rm "${GCS_PREFIX}/${name}.json" 2>/dev/null || true
    done
  fi
}
trap cleanup EXIT

# =============================================================================
# Step 1: Build and push the workload container
# =============================================================================

echo "=== Building and pushing workload container ==="

# Build for linux/amd64 and push to Docker Hub.
docker buildx build \
  --platform linux/amd64 \
  -t "$WORKLOAD_IMAGE" \
  -f "${SCRIPT_DIR}/Dockerfile" \
  --push \
  "$REPO_ROOT"

echo "pushed: ${WORKLOAD_IMAGE}"

# =============================================================================
# Step 2: Create all VMs in parallel
# =============================================================================

create_vm() {
  local name="$1"
  local zone="$2"
  local machine_type="$3"
  local image="$4"
  local hardened="$5"
  shift 5
  # Remaining args are extra gcloud flags (e.g. --confidential-compute-type=TDX).

  local gcs_path="${GCS_PREFIX}/${name}.json"
  echo "creating VM: ${name} (${machine_type} in ${zone}, hardened=${hardened}), GCS output: ${gcs_path}"

  gcloud compute instances create "$name" \
    --project="$PROJECT" \
    --zone="$zone" \
    --machine-type="$machine_type" \
    --scopes=cloud-platform \
    --image="$image" \
    --image-project="$CS_IMAGE_PROJECT" \
    --metadata="tee-image-reference=${WORKLOAD_IMAGE},tee-container-log-redirect=true,tee-env-HARDENED=${hardened},tee-env-GCS_OUTPUT=${gcs_path},self-verification=true" \
    --boot-disk-size=30GB \
    --maintenance-policy=TERMINATE \
    --shielded-secure-boot \
    "$@"

  CREATED_VMS+=("${name}|${zone}")
}

echo ""
echo "=== Creating VMs ==="

# Build a list of VMs to create: (name, zone, machine_type, image, hardened, extra_flags...)
# We'll create them all, then fetch vectors in parallel.

# Arrays to track VM names and zones for fetching.
VM_NAMES=()
VM_ZONES=()
VM_LABELS=()

if [[ -n "$CS_DEBUG_IMAGE" ]]; then
  VM_DBG_TDX="tv-dbg-tdx-${TIMESTAMP}"
  VM_DBG_SEV="tv-dbg-sev-${TIMESTAMP}"
  VM_DBG_SVM="tv-dbg-svm-${TIMESTAMP}"

  create_vm "$VM_DBG_TDX" "$TDX_ZONE" "c3-standard-4" "$CS_DEBUG_IMAGE" "false" \
    --confidential-compute-type=TDX --min-cpu-platform="Intel Sapphire Rapids"
  create_vm "$VM_DBG_SEV" "$SEV_ZONE" "n2d-standard-2" "$CS_DEBUG_IMAGE" "false" \
    --confidential-compute-type=SEV_SNP
  create_vm "$VM_DBG_SVM" "$SVM_ZONE" "n2d-standard-2" "$CS_DEBUG_IMAGE" "false"

  VM_NAMES+=("$VM_DBG_TDX" "$VM_DBG_SEV" "$VM_DBG_SVM")
  VM_ZONES+=("$TDX_ZONE" "$SEV_ZONE" "$SVM_ZONE")
  VM_LABELS+=("debug-TDX" "debug-SEV" "debug-SVM")
fi

if [[ -n "$CS_HARDENED_IMAGE" ]]; then
  VM_HRD_TDX="tv-hrd-tdx-${TIMESTAMP}"
  VM_HRD_SEV="tv-hrd-sev-${TIMESTAMP}"
  VM_HRD_SVM="tv-hrd-svm-${TIMESTAMP}"

  create_vm "$VM_HRD_TDX" "$TDX_ZONE" "c3-standard-4" "$CS_HARDENED_IMAGE" "true" \
    --confidential-compute-type=TDX --min-cpu-platform="Intel Sapphire Rapids"
  create_vm "$VM_HRD_SEV" "$SEV_ZONE" "n2d-standard-2" "$CS_HARDENED_IMAGE" "true" \
    --confidential-compute-type=SEV_SNP
  create_vm "$VM_HRD_SVM" "$SVM_ZONE" "n2d-standard-2" "$CS_HARDENED_IMAGE" "true"

  VM_NAMES+=("$VM_HRD_TDX" "$VM_HRD_SEV" "$VM_HRD_SVM")
  VM_ZONES+=("$TDX_ZONE" "$SEV_ZONE" "$SVM_ZONE")
  VM_LABELS+=("hardened-TDX" "hardened-SEV" "hardened-SVM")
fi

# =============================================================================
# Step 3: Fetch vectors via GCS polling (all VMs in parallel)
# =============================================================================

# fetch_vectors polls GCS for the vector file uploaded by the workload.
# Works with both debug and hardened images (no SSH required).
fetch_vectors() {
  local name="$1"
  local zone="$2"
  local gcs_path="${GCS_PREFIX}/${name}.json"
  local timeout_secs=600  # 10 minutes
  local start=$SECONDS

  echo "polling GCS for ${name} at ${gcs_path}..." >&2

  while (( SECONDS - start < timeout_secs )); do
    local tmpfile
    tmpfile=$(mktemp)

    if gcloud storage cat "$gcs_path" > "$tmpfile" 2>/dev/null; then
      # Verify we got valid JSON.
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
      --project="$PROJECT" --format="value(status)" 2>/dev/null || echo "UNKNOWN")
    if [[ "$status" == "TERMINATED" || "$status" == "STOPPED" ]]; then
      echo "error: VM ${name} stopped before producing vectors" >&2
      return 1
    fi

    sleep 10
  done

  echo "error: timed out waiting for vectors from ${name}" >&2
  return 1
}

echo ""
echo "=== Fetching vectors via GCS ==="

NUM_VMS=${#VM_NAMES[@]}
TMPFILES=()
PIDS=()

for (( i=0; i<NUM_VMS; i++ )); do
  tmpfile=$(mktemp)
  TMPFILES+=("$tmpfile")
  fetch_vectors "${VM_NAMES[$i]}" "${VM_ZONES[$i]}" > "$tmpfile" &
  PIDS+=($!)
done

FAIL=0
for (( i=0; i<NUM_VMS; i++ )); do
  if ! wait "${PIDS[$i]}"; then
    echo "error: ${VM_LABELS[$i]} failed" >&2
    FAIL=1
  fi
done

if [[ "$FAIL" -ne 0 ]]; then
  rm -f "${TMPFILES[@]}"
  exit 1
fi

for (( i=0; i<NUM_VMS; i++ )); do
  count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "${TMPFILES[$i]}" 2>/dev/null || echo '?')
  echo "  ${VM_LABELS[$i]}: captured ${count} vectors"
done

# =============================================================================
# Step 4: Concatenate all vectors and overwrite the output file
# =============================================================================

echo ""
echo "=== Writing vectors ==="

# Build args array for python: label:path pairs.
TMPFILE_ARGS=()
for (( i=0; i<NUM_VMS; i++ )); do
  TMPFILE_ARGS+=("${VM_LABELS[$i]}:${TMPFILES[$i]}")
done

python3 -c "
import json, sys

all_vectors = []
for arg in sys.argv[1:]:
    label, path = arg.split(':', 1)
    try:
        with open(path) as f:
            vectors = json.load(f)
        all_vectors.extend(vectors)
        print(f'  {label}: {len(vectors)} vectors', file=sys.stderr)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f'  {label}: FAILED to parse {path}: {e}', file=sys.stderr)
        sys.exit(1)

print(json.dumps(all_vectors, indent=2))
" "${TMPFILE_ARGS[@]}" > "$OUTPUT_FILE"

rm -f "${TMPFILES[@]}"

echo ""
echo "=== Done ==="
echo "wrote $(python3 -c "import json; print(len(json.load(open('$OUTPUT_FILE'))))" 2>/dev/null || echo '?') vectors to ${OUTPUT_FILE}"
echo ""
echo "Next: run 'go test github.com/Layr-Labs/go-tpm-tools/sdk/attest -v' to verify the vectors."
