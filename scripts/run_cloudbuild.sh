#!/bin/bash
# Run the script: ./scripts/run_cloudbuild.sh [debug|hardened|all]
set -euxo pipefail

BUILD_TYPE="${1:-hardened}"
if [[ "$BUILD_TYPE" != "all" && "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "hardened" ]]; then
  echo "Usage: $0 [debug|hardened|all]"
  exit 1
fi

# Append a timestamp, as there is a check in finish-image-build that checks if
# the image already exists.
IMAGE_SUFFIX="$USER-test-image-`date +%s`"
BUILD_PROJECT="${BUILD_PROJECT:-data-axiom-440223-j1}"

DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
echo "Running Cloud Build on directory $DIR (project: $BUILD_PROJECT, build_type: $BUILD_TYPE)"

# If you get the error:
# googleapi: Error 403: Required 'compute.images.get' permission for 'foo', forbidden
#
# Ensure you grant Cloud Build access to Compute Images:
# https://pantheon.corp.google.com/compute/images?referrer=search&tab=exports&project=$BUILD_PROJECT_ID
gcloud beta builds submit --config=${DIR}/launcher/cloudbuild.yaml \
  --project="$BUILD_PROJECT" \
  --substitutions=_OUTPUT_IMAGE_SUFFIX="${IMAGE_SUFFIX}",_BUILD_TYPE="${BUILD_TYPE}"

echo "Image creation successful."
if [[ "$BUILD_TYPE" == "all" || "$BUILD_TYPE" == "debug" ]]; then
  echo "Create a VM using the debug image eigen-compute-debug-${IMAGE_SUFFIX}"
  echo "gcloud compute instances create confidential-space-test --image=eigen-compute-debug-${IMAGE_SUFFIX} --metadata ..."
fi
if [[ "$BUILD_TYPE" == "all" || "$BUILD_TYPE" == "hardened" ]]; then
  echo "Or use the hardened image eigen-compute-hardened-${IMAGE_SUFFIX}"
fi
