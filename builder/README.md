# Verifiable Image Builder

Build custom Confidential Space images with cryptographic proof linking source code to the final image.

## How It Works

```
Source Code ──> Cloud Build ──> Launcher Container ──> CVM Builder ──> GCE Image
                     │                                      │
                     ↓                                      ↓
              SLSA Provenance                        GCA Attestation
              (proves source)                      (proves TEE + inputs)
```

**Trust chain:**
1. **SLSA provenance** (Cloud Build) proves launcher/builder binaries came from specific commits
2. **GCA attestation** (from CVM) proves build ran in a trusted TEE with specific inputs
3. **Manifest** binds everything together with `nonce = SHA256(manifest)` in the attestation

> **Why container images for launcher?** Cloud Build only generates SLSA provenance for
> artifacts stored in Artifact Registry (container images, Go/Maven/Python/npm packages).
> GCS artifacts do not get provenance. By packaging the launcher binary in a minimal
> `FROM scratch` container, we get Google-signed SLSA provenance that proves the binary
> came from a specific source commit.

## GitHub Actions Workflows

### Release Flow

```
Tag launcher-v* ──> Build Launcher ──┐
                    + provenance     │
                                     ├──> Manual Dispatch ──> Deploy ──> Create Tag
Tag builder-v*  ──> Build Builder  ──┘         │               │             │
                    + provenance               ↓               ↓             ↓
                                           3 versions      GCE Images    image-v0.1.0
                                           (references)    + attestation (on success)
```

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `build-launcher.yml` | Tag `launcher-v*` | Builds launcher container to `cs-build/launcher` |
| `build-builder.yml` | Tag `builder-v*` | Builds builder container to `cs-build/builder` |
| `deploy-builder.yml` | Manual dispatch | Deploys CVM builders, creates GCE images, tags on success |

### Deploying Images

1. Go to **Actions** → **Deploy Builder** → **Run workflow**
2. Enter all three versions:
   - `image_version`: e.g., `v0.1.0`
   - `builder_version`: e.g., `v0.1.0`
   - `launcher_version`: e.g., `v0.1.0`
3. Approve the deployment (requires `production` environment approval)
4. On success, creates tag `image-v0.1.0` with builder/launcher versions in message

### Building Components Separately

```bash
# Build launcher (creates tag, triggers workflow)
git tag launcher-v0.1.0 && git push origin launcher-v0.1.0

# Build builder (creates tag, triggers workflow)
git tag builder-v0.1.0 && git push origin builder-v0.1.0
```

## Quick Start (Manual)

### 1. Build Launcher (with SLSA Provenance)

```bash
gcloud builds submit \
  --config=builder/cloudbuild-launcher.yaml \
  --substitutions=_VERSION=v1.0.0,_REGION=us-central1
```

This pushes to `${REGION}-docker.pkg.dev/${PROJECT_ID}/cs-build/launcher:${VERSION}`

### 2. Build Builder Container (with SLSA Provenance)

```bash
gcloud builds submit \
  --config=builder/cloudbuild-builder.yaml \
  --substitutions=_VERSION=v1.0.0,_REGION=us-central1
```

This pushes to `${REGION}-docker.pkg.dev/${PROJECT_ID}/cs-build/builder:${VERSION}`

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
  --metadata=^~^tee-image-reference=$BUILDER_IMAGE~tee-restart-policy=Never~tee-container-log-redirect=true~tee-env-PROJECT_ID=$PROJECT_ID~tee-env-PROJECT_NUMBER=$PROJECT_NUMBER~tee-env-LAUNCHER_ARTIFACT=docker://us-central1/$PROJECT_ID/cs-build/launcher/v1.0.0~tee-env-BASE_IMAGE=cos-tdx-113-18244-521-56~tee-env-BASE_IMAGE_PROJECT=confidential-vm-images~tee-env-OUTPUT_IMAGE_NAME=my-cs-image~tee-env-OUTPUT_IMAGE_FAMILY=custom-cs-images~tee-env-IMAGE_ENV=hardened~tee-env-STAGING_BUCKET=$STAGING_BUCKET~tee-env-PROVENANCE_BUCKET=$PROVENANCE_BUCKET
```

Output: GCE image + attestation in `gs://$PROVENANCE_BUCKET/$OUTPUT_IMAGE_NAME/attestation.json`

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `PROJECT_ID` | GCP project ID |
| `PROJECT_NUMBER` | GCP project number |
| `LAUNCHER_ARTIFACT` | `docker://REGION/PROJECT/REPO/IMAGE/VERSION` (e.g., `docker://us-central1/my-project/cs-build/launcher/v1.0.0`) |
| `BASE_IMAGE` | Source COS image name |
| `BASE_IMAGE_PROJECT` | Project containing base image |
| `OUTPUT_IMAGE_NAME` | Name for the output image |
| `IMAGE_ENV` | `debug` or `hardened` |
| `STAGING_BUCKET` | GCS bucket for cos-customizer temp files (private) |
| `PROVENANCE_BUCKET` | GCS bucket for attestations (public read) |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_IMAGE_FAMILY` | (none) | Image family for the output image |
| `GCA_ENDPOINT` | `https://confidentialcomputing.googleapis.com` | GCA service endpoint |
| `ZONE` | `us-central1-a` | Zone for cos-customizer VM |
| `OEM_SIZE` | `500M` | OEM partition size |
| `DISK_SIZE_GB` | `11` | Output image disk size |
| `BUILD_TIMEOUT_SECONDS` | `3000` | Cloud Build timeout |

## Verification

```bash
# 1. Download attestation
gsutil cat gs://$PROVENANCE_BUCKET/$IMAGE_NAME/attestation.json > attestation.json

# 2. Verify GCA JWT signature (use Google's public key)
# 3. Verify: JWT.eat_nonce == SHA256(manifest)
# 4. Verify launcher/builder SLSA provenance signatures
# 5. Check manifest.output.id matches your image
```

## Manifest Format

```json
{
  "version": "1",
  "timestamp": "2026-01-04T18:58:09Z",
  "source": {
    "launcher": {
      "sha256": "4e63ab578ab902aaddbbe59609424aa...",
      "image_digest": "sha256:abc123...",
      "provenance_ref": "https://us-central1-docker.pkg.dev/project/cs-build/launcher@sha256:abc123...",
      "signature": {
        "keyid": "google-cloud-build",
        "sig": "base64-encoded-signature..."
      }
    },
    "builder": {
      "sha256": "aed385f3ad42e07b68c71d6fb7aa095...",
      "provenance_ref": "https://us-central1-docker.pkg.dev/project/cs-build/builder@sha256:def456...",
      "signature": {
        "keyid": "google-cloud-build",
        "sig": "base64-encoded-signature..."
      }
    }
  },
  "builder_images": {
    "gcr.io/cloud-builders/docker": "sha256:176cb3049e05d24cfda56e986e61bb...",
    "gcr.io/cloud-builders/gcloud": "sha256:62073adbbf97c41cea6ee59db448a7...",
    "gcr.io/cos-cloud/cos-customizer": "sha256:6753dd798f05aad530d913b2df62ec..."
  },
  "base_image": {
    "name": "cos-tdx-113-18244-521-56",
    "project": "confidential-vm-images"
  },
  "output": {
    "name": "cs-image-0-1-0-hardened",
    "id": "2141778560127797559",
    "project": "my-project"
  },
  "cloud_build_id": "46c0cc8d-5826-4d5e-a936-2dc38b0e347a"
}
```

The `builder_images` field captures the SHA256 digests of the container images used during the Cloud Build, providing cryptographic binding to the exact versions of cos-customizer and other tools used.

## Files

| File | Description |
|------|-------------|
| `main.go` | Orchestrator entrypoint |
| `provenance.go` | SLSA provenance fetching |
| `cloudbuild.go` | Cloud Build API (triggers cos-customizer) |
| `source.go` | Uploads cos-customizer scripts to GCS |
| `manifest.go` | Manifest structure and creation |
| `attestation.go` | GCA attestation + storage |
| `cloudbuild-launcher.yaml` | Launcher build config |
| `cloudbuild-builder.yaml` | Builder container build config |
| `Dockerfile` | Builder container image |
| `test-action.sh` | Local testing script (mirrors GitHub Action) |

## Security Notes

**TOCTOU Protection:** The builder uploads `source.tar.gz` (cos-customizer scripts) to GCS
and pins Cloud Build to the exact object generation. This prevents an attacker with bucket
write access from swapping the archive between upload and fetch.

**Bundled Scripts:** The builder container includes cos-customizer scripts from `launcher/image/`
(preload.sh, fixup_oem.sh, etc.). These are copied during `cloudbuild-builder.yaml` and
uploaded to GCS at runtime before triggering the image build.

**Image ID Binding:** The GCE image ID in the manifest is a unique, immutable identifier
assigned by Google. It cannot be reused or reassigned, providing strong binding between
the manifest and the actual image.
