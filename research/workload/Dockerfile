FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o workload main.go

FROM alpine:latest

LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_env_override"="KMS_URL"

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/workload /workload

ENTRYPOINT ["/workload"]
