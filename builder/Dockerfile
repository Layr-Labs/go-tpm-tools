# Build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source
COPY *.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /builder .

# Runtime stage - minimal image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY --from=builder /builder /builder

# Copy cos-customizer scripts (copied into build context by cloudbuild-builder.yaml)
# These are uploaded to GCS as source.tar.gz before triggering Cloud Build
COPY scripts/ /scripts/

# Allow environment variable overrides and log redirect in Confidential Space
LABEL "tee.launch_policy.allow_env_override"="PROJECT_ID,PROJECT_NUMBER,LAUNCHER_ARTIFACT,BASE_IMAGE,BASE_IMAGE_PROJECT,OUTPUT_IMAGE_NAME,OUTPUT_IMAGE_FAMILY,STAGING_BUCKET,PROVENANCE_BUCKET,GCA_ENDPOINT,IMAGE_ENV,ZONE,OEM_SIZE,DISK_SIZE_GB,BUILD_TIMEOUT_SECONDS"
LABEL "tee.launch_policy.log_redirect"="always"

# The builder runs as a batch job in Confidential Space
# No ports need to be exposed
ENTRYPOINT ["/builder"]
