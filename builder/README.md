# Verifiable Image Builder

Build custom Confidential Space images with cryptographic proof linking source code to the final image.

## How It Works

```
Source Code ──> Cloud Build ──> Launcher Container ──> CVM Builder ──> GCE Image
                     │                                      │
                     ↓                                      │
              SLSA Provenance                               ├──> PCR Capture (TDX, SEV-SNP, Shielded)
              (proves source)                               │         │
                                                            │         ↓
                                                            ├──> Manifest (with pcrs)
                                                            │
                                                            ↓
                                                      GCA Attestation
                                                    (proves TEE + inputs)
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
(only if changed)
Tag launcher-v*    ──> Build Launcher    ──┐
                       + provenance        │
                                           ├──> Deploy ──> candidate
Tag builder-v*     ──> Build Builder     ──┤                  │
                       + provenance        │                  │
                                           │                  │
Tag pcr-capture-v* ──> Build PCR Capture ──┘                  │
                       + provenance                           │
                                                              ↓
                                           propose_pcrs.sh dev   ──> Sepolia Safe (async approval)
                                           propose_pcrs.sh prod  ──> Mainnet Safe (async approval)
                                                              │
                                           Promote to dev  ───┤──> copy to dev family (no approval)
                                                              │
                                           Promote to prod ───┘──> move to prod family (requires approval)
```

Container builds are only needed when *those* components have changed. In practice the launcher changes most often and usually needs a fresh tag, while `builder` and `pcr-capture` are mostly stable and reused across releases.

### Image Lifecycle

| Tier | Family | Image | Access | Approval |
|------|--------|-------|--------|----------|
| candidate | `cs-image-{env}-candidate` | Original (e.g., `cs-image-0-1-0-hardened`) | Project-only | None (auto after build) |
| dev | `cs-image-{env}-dev` | Copy (e.g., `cs-image-0-1-0-hardened-dev`) | Project-only | None |
| prod | `cs-image-{env}` | Original (moved from candidate) | `allAuthenticatedUsers` | Required |

Dev promotion **copies** the image (original stays in candidate). Prod promotion **moves** the original to prod (preserving its attestation chain). The dev copy persists, so images remain discoverable in the dev family after prod promotion.

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `cloudbuild-launcher.yaml` | Tag `launcher-v*` | Builds launcher container to `cs-build/launcher` |
| `cloudbuild-builder.yaml` | Tag `builder-v*` | Builds builder container to `cs-build/builder` |
| `cloudbuild-pcr-capture.yaml` | Tag `pcr-capture-v*` | Builds PCR capture container to `cs-build/pcr-capture` |
| `deploy-builder.yml` | Manual dispatch | Deploys CVM builders, creates candidate GCE images |
| `promote-image.yml` | Manual dispatch | Promotes images: candidate → dev → prod |

### Deploying Images

1. Go to **Actions** → **Deploy Builder** → **Run workflow**
2. Enter all four versions:
   - `image_version`: e.g., `v0.1.0`
   - `builder_version`: e.g., `v0.1.0`
   - `launcher_version`: e.g., `v0.1.0`
   - `pcr_capture_version`: e.g., `v0.1.0`
3. On success, images are created as **candidates** (project-private, `cs-image-{env}-candidate` family)

### Proposing PCRs On-Chain

After candidates are built and *before* promoting to dev or prod, the new image's PCRs must be added to the on-chain `ImageAllowlist` so that VMs running this image will pass attestation. This is done via a Safe multisig proposal — propose now so signers have time to approve while you're still verifying the image.

Pipe the build manifest straight into `propose_pcrs.sh` via `MANIFEST_JSON=-`. The script extracts `.pcrs` and derives `IMAGE_VERSION` and `IMAGE_DESCRIPTION` from `.output.name`, so the on-chain version is guaranteed to match the manifest the PCRs came from:

```bash
IMAGE=cs-image-0-1-2-hardened

gsutil cat gs://$PROVENANCE_BUCKET/$IMAGE/attestation.json \
  | MANIFEST_JSON=- PROPOSER_PRIVATE_KEY=0x... \
    ./scripts/propose_pcrs.sh dev    # Sepolia

gsutil cat gs://$PROVENANCE_BUCKET/$IMAGE/attestation.json \
  | MANIFEST_JSON=- PROPOSER_PRIVATE_KEY=0x... \
    ./scripts/propose_pcrs.sh prod   # Mainnet
```

`MANIFEST_JSON` is required and accepts a file path or `-` for stdin. The script bundles the three platform `addImages` calls (TDX, SEV-SNP, Shielded VM) into a single `MultiSendCallOnly` transaction, signs with the proposer key, and posts to the Safe Transaction Service. It prints a Safe app URL where the remaining signers approve and execute.

| Network | Safe | ImageAllowlist | Chain |
|---------|------|----------------|-------|
| dev | `0xb094Ba76…3b0` | `0x6B6Ce40D…E86e` | Sepolia |
| prod | `0x684cf897…e09` | `0xb4713c7C…4d72` | Mainnet |

> **Prereqs:** `cast` (Foundry), `python3`, `jq`. The proposer key must belong to a Safe owner on the target network.

### Promoting Images

1. **Confirm** the corresponding Safe proposal from [Proposing PCRs On-Chain](#proposing-pcrs-on-chain) has been **executed** on the target network (dev → Sepolia, prod → Mainnet). Promoting before the allowlist is updated will leave VMs unable to attest.
2. Go to **Actions** → **Promote Image** → **Run workflow**
3. Enter the **original** image name (e.g., `cs-image-0-1-0-hardened`) and target tier (`dev` or `prod`)
4. Promotion enforces a strict path: candidate → dev → prod
   - **Dev**: Creates a copy (`cs-image-0-1-0-hardened-dev`) in the dev family. Original stays in candidate.
   - **Prod**: Verifies the dev copy exists (proves it went through dev), then moves the original to the prod family. Dev copy persists.
5. Promoting to **prod** requires `production` environment approval, makes the image public, and creates a git tag

### Building Components Separately

Only required when the corresponding component's source has changed since the last release. Otherwise reuse the existing container versions in `deploy-builder.yml`.

```bash
# Build launcher (creates tag, triggers Cloud Build)
git tag launcher-v0.1.0 && git push origin launcher-v0.1.0

# Build builder (creates tag, triggers Cloud Build)
git tag builder-v0.1.0 && git push origin builder-v0.1.0

# Build PCR capture (creates tag, triggers Cloud Build)
git tag pcr-capture-v0.1.0 && git push origin pcr-capture-v0.1.0
```

## Local Development Iteration

For testing image changes on a feature branch *without* going through the release flow. These scripts target a developer scratch project (`data-axiom-440223-j1` by default) and the **Sepolia** chain — they never touch production GCP projects, the prod image registry, or the mainnet Safe.

### Build a test image — `scripts/run_cloudbuild.sh`

```bash
./scripts/run_cloudbuild.sh hardened   # or: debug | all
```

Submits `launcher/cloudbuild.yaml` to Cloud Build in `$BUILD_PROJECT` and produces an image named `eigen-compute-{type}-$USER-test-image-{timestamp}`. The timestamp suffix avoids collisions with the `finish-image-build` "already exists" check.

| Variable | Default | Purpose |
|----------|---------|---------|
| `BUILD_PROJECT` | `data-axiom-440223-j1` | Scratch GCP project |

Use the resulting image directly with `gcloud compute instances create --image=...`, or feed it into `deploy_to_dev.sh` for an end-to-end Sepolia test.

### End-to-end dev preview — `scripts/deploy_to_dev.sh`

```bash
IMAGE_NAME=eigen-compute-hardened-$USER-test-image-1700000000 \
PROPOSER_PRIVATE_KEY=0x... \
./scripts/deploy_to_dev.sh
```

Three phases against an existing hardened image in `$BUILD_PROJECT`:

1. **PCR capture** — boots three VMs (TDX, SEV-SNP, Shielded) with the `pcr-capture` workload, polls GCS for each output, merges into `scripts/pcrs.json`.
2. **Image promotion** — copies the image into `tee-compute-global` as `${IMAGE_NAME}-preview` in the `cs-image-hardened-dev` family, grants `roles/compute.imageUser` to the dev project's instance-creator SA.
3. **Sepolia Safe proposal** — encodes `addImages` for all three platforms, packs into a `MultiSendCallOnly` transaction, signs, and posts to the Safe Transaction Service. Prints a Safe app URL for remaining signers.

Hardened images only — debug images aren't supported. Prereqs: `gcloud`, `cast` (Foundry), `python3`, `jq`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `IMAGE_NAME` | *(required)* | Source hardened image in `$BUILD_PROJECT` |
| `PROPOSER_PRIVATE_KEY` | *(required)* | Safe owner key on Sepolia |
| `BUILD_PROJECT` | `data-axiom-440223-j1` | Where the source image lives |
| `GLOBAL_IMAGE_PROJECT` | `tee-compute-global` | Where the dev copy is published |
| `DEV_PROJECT` | `tee-compute-sepolia-dev` | Dev environment that gets IAM access |
| `IMAGE_VERSION` | `git rev-parse --short HEAD` | Embedded in the on-chain `Image.version` |

> **Not a release path.** Test images created here are tagged `*-preview` and never get promoted to prod via `promote-image.yml`. To release for real, go through the [Release Flow](#release-flow).

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
| `PCR_CAPTURE_IMAGE` | PCR capture container image (e.g., `us-central1-docker.pkg.dev/proj/cs-build/pcr-capture:v0.1.0`) |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_IMAGE_FAMILY` | (none) | Image family for the output image |
| `GCA_ENDPOINT` | `https://confidentialcomputing.googleapis.com` | GCA service endpoint |
| `ZONE` | `us-central1-a` | Zone for cos-customizer VM |
| `OEM_SIZE` | `500M` | OEM partition size |
| `DISK_SIZE_GB` | `11` | Output image disk size |
| `BUILD_TIMEOUT_SECONDS` | `3000` | Cloud Build timeout |
| `SEV_ZONE` | same as `ZONE` | Zone with SEV-SNP support for PCR capture VMs |

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
  "cloud_build_id": "46c0cc8d-5826-4d5e-a936-2dc38b0e347a",
  "pcrs": {
    "intel_tdx": {
      "pcr4": "a1b2c3d4...",
      "pcr8": "e5f6a7b8...",
      "pcr9": "c9d0e1f2..."
    },
    "amd_sev_snp": {
      "pcr4": "1a2b3c4d...",
      "pcr8": "5e6f7a8b...",
      "pcr9": "9c0d1e2f..."
    },
    "gcp_shielded_vm": {
      "pcr4": "f1e2d3c4...",
      "pcr8": "b5a6f7e8...",
      "pcr9": "d9c0b1a2..."
    }
  }
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
| `pcr.go` | PCR capture orchestration (boots VMs, collects PCRs) |
| `pcr_capture/` | PCR capture workload (runs inside CVM) |
| `cloudbuild-launcher.yaml` | Launcher build config |
| `cloudbuild-builder.yaml` | Builder container build config |
| `cloudbuild-pcr-capture.yaml` | PCR capture container build config |
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
