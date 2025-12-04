#!/bin/bash
# Run the script: ./run_cloudbuild.sh
# Builds a debug Confidential Space image using your local source code.
set -euo pipefail

# Append a timestamp, as there is a check in finish-image-build that checks if
# the image already exists.
IMAGE_SUFFIX="$USER-test-image-$(date +%s)"
IMAGE_NAME="confidential-space-debug-${IMAGE_SUFFIX}"

# Get the directory where this script lives
DIR=$(dirname -- "${BASH_SOURCE[0]}")
cd "$DIR"

echo "Running Cloud Build from directory: $(pwd)"

# Get project ID
PROJECT_ID=$(gcloud config get-value project)
BUCKET_NAME="${PROJECT_ID}_cloudbuild"

# Get the latest base image from the cos-tdx family
BASE_IMAGE=$(gcloud compute images describe-from-family cos-tdx-113-lts \
  --project=confidential-vm-images --format='value(name)')

echo "Using base image: ${BASE_IMAGE}"
echo "Building image: ${IMAGE_NAME}"

# Build the debug image directly (bypasses the worker pool requirement)
gcloud beta builds submit --config=launcher/image/cloudbuild.yaml \
  --region=us-west1 \
  --substitutions=_BASE_IMAGE=${BASE_IMAGE},\
_BASE_IMAGE_PROJECT=confidential-vm-images,\
_OUTPUT_IMAGE_NAME=${IMAGE_NAME},\
_OUTPUT_IMAGE_FAMILY=,\
_IMAGE_ENV=debug,\
_CS_LICENSE=projects/confidential-space-images/global/licenses/confidential-space-debug,\
_BUCKET_NAME=${BUCKET_NAME},\
_SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo ""
echo "Image creation successful!"
echo ""
echo "Create a VM using:"
echo "  gcloud compute instances create my-cs-vm \\"
echo "    --image=${IMAGE_NAME} \\"
echo "    --image-project=${PROJECT_ID} \\"
echo "    --machine-type=n2d-standard-2 \\"
echo "    --confidential-compute \\"
echo "    --shielded-secure-boot \\"
echo "    --metadata=tee-image-reference=YOUR_CONTAINER_IMAGE"
