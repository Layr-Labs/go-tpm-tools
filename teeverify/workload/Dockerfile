FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY proto/ ./proto/
COPY teeverify/workload/main.go ./teeverify/workload/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o workload ./teeverify/workload/

FROM --platform=linux/amd64 alpine:latest
LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_env_override"="HARDENED,GCS_OUTPUT"
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/workload /workload
ENTRYPOINT ["/workload"]
