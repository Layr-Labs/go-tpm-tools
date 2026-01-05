#!/bin/bash
set -e

VERSION="v0.12.0"
LAUNCHER_VERSION="v0.3.0"
PROJECT="data-axiom-440223-j1"
PROJECT_NUMBER="525298585311"
ZONE="us-central1-a"
IMAGE_NAME="test-cs-image-v13"
BUCKET="compute-base-images"
REGION="us-central1"
AR_REPO="builders"

cd "$(dirname "$0")/../.."

# 0. Ensure Artifact Registry repositories exist
echo "=== Ensuring Artifact Registry repositories exist ==="
gcloud artifacts repositories describe ${AR_REPO} \
  --location=${REGION} \
  --project=${PROJECT} 2>/dev/null || \
gcloud artifacts repositories create ${AR_REPO} \
  --repository-format=docker \
  --location=${REGION} \
  --project=${PROJECT}

# Ensure Docker launcher repository exists (for SLSA provenance)
gcloud artifacts repositories describe launcher \
  --location=${REGION} \
  --project=${PROJECT} 2>/dev/null || \
(gcloud artifacts repositories create launcher \
  --repository-format=docker \
  --location=${REGION} \
  --project=${PROJECT} \
  --description="Launcher container images with SLSA provenance" && \
gcloud artifacts repositories add-iam-policy-binding launcher \
  --location=${REGION} \
  --project=${PROJECT} \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/artifactregistry.writer")

# 1. Build launcher with SLSA provenance (uploads to Artifact Registry)
echo "=== Building launcher with provenance ==="
gcloud builds submit --config=research/builder/cloudbuild-launcher.yaml \
  --substitutions=_VERSION=${LAUNCHER_VERSION},_REGION=${REGION},_OUTPUT_BUCKET=${BUCKET} \
  --project=${PROJECT}

# 2. Build builder container with SLSA provenance via Cloud Build
echo "=== Building builder container with provenance ==="
gcloud builds submit --config=research/builder/cloudbuild-builder.yaml \
  --substitutions=_VERSION=${VERSION},_REGION=${REGION} \
  --project=${PROJECT}

# 3. Delete old test image (if exists)
echo "=== Cleaning up old resources ==="
gcloud compute images delete ${IMAGE_NAME} --project=${PROJECT} --quiet 2>/dev/null || true
gcloud compute instances delete cs-builder-test --zone=${ZONE} --project=${PROJECT} --quiet 2>/dev/null || true

# 4. Deploy the CVM builder using Artifact Registry image
echo "=== Deploying CVM builder ==="
AR_IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}/cs-builder:${VERSION}"
gcloud compute instances create cs-builder-test \
  --zone=${ZONE} \
  --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX \
  --shielded-secure-boot \
  --maintenance-policy=TERMINATE \
  --image-family=confidential-space-debug \
  --image-project=confidential-space-images \
  --scopes=cloud-platform \
  --project=${PROJECT} \
  --metadata=^~^tee-image-reference=${AR_IMAGE}~tee-restart-policy=Never~tee-container-log-redirect=true~tee-env-PROJECT_ID=${PROJECT}~tee-env-PROJECT_NUMBER=${PROJECT_NUMBER}~tee-env-LAUNCHER_ARTIFACT=docker://${REGION}/${PROJECT}/launcher/launcher/${LAUNCHER_VERSION}~tee-env-BASE_IMAGE=cos-tdx-113-18244-521-56~tee-env-BASE_IMAGE_PROJECT=confidential-vm-images~tee-env-OUTPUT_IMAGE_NAME=${IMAGE_NAME}~tee-env-OUTPUT_IMAGE_FAMILY=custom-cs-images~tee-env-ATTESTATION_BUCKET=${BUCKET}~tee-env-CLOUDBUILD_BUCKET=${BUCKET}~tee-env-GCA_ENDPOINT=https://confidentialcomputing.googleapis.com

echo ""
echo "=== Deployed ==="
echo "Watch logs with:"
echo "  gcloud compute instances get-serial-port-output cs-builder-test --zone=${ZONE} --project=${PROJECT}"
echo ""
echo "Check attestation with:"
echo "  gsutil cat gs://${BUCKET}/build-attestations/${IMAGE_NAME}/attestation.json | python3 -m json.tool"
