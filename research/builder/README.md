# Verifiable Image Builder

Build custom Confidential Space images with cryptographic proof linking source code to the final image.

## How It Works

```
Source Code ──> Cloud Build ──> Launcher Binary ──> CVM Builder ──> GCE Image
                     │                                   │
                     ↓                                   ↓
              SLSA Provenance                     GCA Attestation
              (proves source)                   (proves TEE + inputs)
```

**Trust chain:**
1. **SLSA provenance** (Cloud Build) proves launcher/builder binaries came from specific commits
2. **GCA attestation** (from CVM) proves build ran in a trusted TEE with specific inputs
3. **Manifest** binds everything together with `nonce = SHA256(manifest)` in the attestation

## Quick Start

### 1. Build Launcher (with SLSA Provenance)

```bash
gcloud builds submit \
  --config=research/builder/cloudbuild-launcher.yaml \
  --substitutions=_VERSION=v1.0.0,_REGION=us-central1,_OUTPUT_BUCKET=my-bucket
```

### 2. Build Builder Container (with SLSA Provenance)

```bash
gcloud builds submit \
  --config=research/builder/cloudbuild-builder.yaml \
  --substitutions=_VERSION=v1.0.0,_REGION=us-central1
```

### 3. Deploy CVM Builder

```bash
gcloud compute instances create cs-builder \
  --zone=us-central1-a \
  --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX \
  --shielded-secure-boot \
  --maintenance-policy=TERMINATE \
  --image-family=confidential-space \
  --image-project=confidential-space-images \
  --scopes=cloud-platform \
  --metadata=^~^tee-image-reference=$BUILDER_IMAGE~tee-restart-policy=Never~tee-container-log-redirect=true~tee-env-PROJECT_ID=$PROJECT_ID~tee-env-PROJECT_NUMBER=$PROJECT_NUMBER~tee-env-LAUNCHER_ARTIFACT=docker://$REGION/$PROJECT_ID/launcher/launcher/v1.0.0~tee-env-BASE_IMAGE=cos-tdx-113-18244-521-56~tee-env-BASE_IMAGE_PROJECT=confidential-vm-images~tee-env-OUTPUT_IMAGE_NAME=my-cs-image~tee-env-OUTPUT_IMAGE_FAMILY=custom-cs-images~tee-env-ATTESTATION_BUCKET=$BUCKET~tee-env-CLOUDBUILD_BUCKET=$BUCKET
```

Output: GCE image + attestation in `gs://$ATTESTATION_BUCKET/build-attestations/$OUTPUT_IMAGE_NAME/attestation.json`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PROJECT_ID` | GCP project ID |
| `PROJECT_NUMBER` | GCP project number |
| `LAUNCHER_ARTIFACT` | `docker://REGION/PROJECT/REPO/IMAGE/VERSION` |
| `BASE_IMAGE` | Source COS image name |
| `BASE_IMAGE_PROJECT` | Project containing base image |
| `OUTPUT_IMAGE_NAME` | Name for the output image |
| `OUTPUT_IMAGE_FAMILY` | Image family (optional) |
| `ATTESTATION_BUCKET` | GCS bucket for attestation storage |
| `CLOUDBUILD_BUCKET` | GCS bucket for cos-customizer work |

## Verification

```bash
# 1. Download attestation
gsutil cat gs://$BUCKET/build-attestations/$IMAGE_NAME/attestation.json > attestation.json

# 2. Verify GCA JWT signature (use Google's public key)
# 3. Verify: JWT.eat_nonce == SHA256(manifest)
# 4. Verify launcher/builder SLSA provenance signatures
# 5. Check manifest.output.image_id matches your image
```

## Manifest Format

```json
{
  "version": "1",
  "timestamp": "2026-01-04T18:58:09Z",
  "source": {
    "launcher": {
      "sha256": "4e63ab578ab902aaddbbe59609424aa...",
      "provenance": { /* SLSA provenance embedded */ }
    },
    "builder": {
      "sha256": "aed385f3ad42e07b68c71d6fb7aa095...",
      "provenance": { /* SLSA provenance embedded */ }
    }
  },
  "base_image": {
    "name": "cos-tdx-113-18244-521-56",
    "project": "confidential-vm-images"
  },
  "output": {
    "image_id": "2141778560127797559",
    "image_name": "my-cs-image",
    "project": "my-project"
  },
  "cloud_build_id": "46c0cc8d-5826-4d5e-a936-2dc38b0e347a"
}
```

## Files

| File | Description |
|------|-------------|
| `main.go` | Orchestrator entrypoint |
| `provenance.go` | SLSA provenance fetching |
| `cloudbuild.go` | Cloud Build API |
| `attestation.go` | GCA attestation + storage |
| `cloudbuild-launcher.yaml` | Launcher build config |
| `cloudbuild-builder.yaml` | Builder container build config |
| `Dockerfile` | Builder container image |
| `deploy.sh` | Deployment script |
