#!/bin/bash
# TDX Attestation Demo
#
# Demonstrates raw TDX attestation with:
#   - KMS server that verifies attestations against a Sepolia contract
#   - TDX workload running in Confidential Space
#
# Prerequisites:
#   1. Run setup.sh to deploy contract and add base image measurements
#   2. Set environment variables or create config.env
#
# Usage:
#   ./run.sh          # Run the full demo
#   ./run.sh logs     # Stream logs from running VMs
#   ./run.sh cleanup  # Delete all VMs

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESEARCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$RESEARCH_DIR/config.env"

# Load config
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# Configuration (override via environment or config.env)
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${ZONE:-us-central1-a}"
DOCKER_REPO="${DOCKER_REPO:-docker.io/cavaneigen}"
CS_IMAGE="${CS_IMAGE:-confidential-space-debug-cavan-test-image-1764789757}"
CS_IMAGE_PROJECT="${CS_IMAGE_PROJECT:-$PROJECT_ID}"

# Derived values
KMS_INSTANCE="research-kms"
TDX_INSTANCE="research-tdx-workload"
KMS_IMAGE="$DOCKER_REPO/research-kms:latest"
WORKLOAD_IMAGE="$DOCKER_REPO/research-workload:latest"

# Colors
log() { echo -e "\033[0;32m[$(date '+%H:%M:%S')]\033[0m $1"; }
warn() { echo -e "\033[1;33m[$(date '+%H:%M:%S')] WARNING:\033[0m $1"; }
error() { echo -e "\033[0;31m[$(date '+%H:%M:%S')] ERROR:\033[0m $1"; exit 1; }

check_config() {
    [ -n "$PROJECT_ID" ] || error "PROJECT_ID not set"
    [ -n "$CONTRACT_ADDR" ] || error "CONTRACT_ADDR not set. Run ./setup.sh deploy first."
    [ -n "$SEPOLIA_RPC_URL" ] || error "SEPOLIA_RPC_URL not set"
}

build() {
    log "Building KMS..."
    cd "$RESEARCH_DIR/kms"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kms .
    docker build --platform linux/amd64 -t "$KMS_IMAGE" .
    docker push "$KMS_IMAGE"
    rm kms
    log "KMS image pushed: $KMS_IMAGE"

    log "Building workload..."
    cd "$RESEARCH_DIR/workload"
    docker build --platform linux/amd64 -t "$WORKLOAD_IMAGE" .
    docker push "$WORKLOAD_IMAGE"
    log "Workload image pushed: $WORKLOAD_IMAGE"
}

deploy_kms() {
    log "Deploying KMS VM..."

    # Delete if exists
    gcloud compute instances delete "$KMS_INSTANCE" --zone="$ZONE" --project="$PROJECT_ID" --quiet 2>/dev/null || true

    gcloud compute instances create-with-container "$KMS_INSTANCE" \
        --zone="$ZONE" \
        --project="$PROJECT_ID" \
        --machine-type=e2-medium \
        --tags=http-server \
        --container-image="$KMS_IMAGE" \
        --container-env="CONTRACT_ADDR=$CONTRACT_ADDR,ETH_RPC_URL=$SEPOLIA_RPC_URL"

    # Firewall rule
    gcloud compute firewall-rules create allow-kms-8080 \
        --project="$PROJECT_ID" --allow=tcp:8080 --target-tags=http-server --quiet 2>/dev/null || true

    # Wait for IP
    sleep 10
    KMS_IP=$(gcloud compute instances describe "$KMS_INSTANCE" \
        --zone="$ZONE" --project="$PROJECT_ID" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
    echo "$KMS_IP" > /tmp/kms_ip.txt
    log "KMS IP: $KMS_IP"

    # Wait for health
    log "Waiting for KMS to be ready..."
    for i in {1..30}; do
        curl -s "http://$KMS_IP:8080/health" | grep -q "ok" && { log "KMS ready!"; return 0; }
        sleep 5
    done
    error "KMS did not become ready"
}

deploy_tdx() {
    KMS_IP=$(cat /tmp/kms_ip.txt 2>/dev/null) || error "KMS IP not found. Deploy KMS first."
    log "Deploying TDX workload VM..."

    # Delete if exists
    gcloud compute instances delete "$TDX_INSTANCE" --zone="$ZONE" --project="$PROJECT_ID" --quiet 2>/dev/null || true

    gcloud compute instances create "$TDX_INSTANCE" \
        --zone="$ZONE" \
        --project="$PROJECT_ID" \
        --machine-type=c3-standard-4 \
        --confidential-compute-type=TDX \
        --shielded-secure-boot \
        --image="$CS_IMAGE" \
        --image-project="$CS_IMAGE_PROJECT" \
        --maintenance-policy=TERMINATE \
        --scopes=cloud-platform \
        --metadata="tee-image-reference=$WORKLOAD_IMAGE,tee-container-log-redirect=true,tee-env-KMS_URL=http://$KMS_IP:8080"

    log "TDX workload VM deployed"
}

stream_logs() {
    log "Streaming logs (Ctrl+C to stop)..."

    # KMS logs in background
    (gcloud compute ssh "$KMS_INSTANCE" --zone="$ZONE" --project="$PROJECT_ID" -- \
        "sudo docker logs -f \$(sudo docker ps -q)" 2>/dev/null | sed "s/^/[KMS] /" &)

    # TDX logs
    while true; do
        gcloud logging read "resource.type=gce_instance AND resource.labels.instance_id:$TDX_INSTANCE" \
            --project="$PROJECT_ID" --freshness=1m --format="value(textPayload)" --limit=10 2>/dev/null | \
            grep -v "^$" | tail -5
        sleep 5
    done
}

cleanup() {
    log "Cleaning up VMs..."
    gcloud compute instances delete "$KMS_INSTANCE" --zone="$ZONE" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    gcloud compute instances delete "$TDX_INSTANCE" --zone="$ZONE" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    rm -f /tmp/kms_ip.txt
    log "Done"
}

run_demo() {
    check_config
    log "Starting TDX Attestation Demo"
    log "  Project: $PROJECT_ID"
    log "  Contract: $CONTRACT_ADDR (Sepolia)"
    log "  Base image: $CS_IMAGE"
    echo ""

    build
    deploy_kms
    deploy_tdx

    echo ""
    log "=== Demo Running ==="
    log "KMS: http://$(cat /tmp/kms_ip.txt):8080"
    log ""
    log "View logs:    ./run.sh logs"
    log "Cleanup:      ./run.sh cleanup"
    log ""
    log "If base image not in allowlist, add it with:"
    log "  ./setup.sh add-image --mrtd 0x... --rtmr0 0x... --rtmr1 0x..."
}

case "${1:-run}" in
    run|"")   run_demo ;;
    logs)     stream_logs ;;
    cleanup)  cleanup ;;
    build)    build ;;
    kms)      check_config; deploy_kms ;;
    tdx)      deploy_tdx ;;
    *)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (none)    Run the full demo"
        echo "  logs      Stream logs from VMs"
        echo "  cleanup   Delete all VMs"
        echo ""
        echo "Advanced:"
        echo "  build     Build Docker images only"
        echo "  kms       Deploy KMS VM only"
        echo "  tdx       Deploy TDX workload VM only"
        ;;
esac
