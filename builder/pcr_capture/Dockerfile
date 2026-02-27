FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY proto/ ./proto/
COPY builder/pcr_capture/ ./builder/pcr_capture/
RUN cd builder/pcr_capture && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/pcr-capture .

FROM alpine:latest
LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_env_override"="GCS_OUTPUT"
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/pcr-capture /pcr-capture
ENTRYPOINT ["/pcr-capture"]
