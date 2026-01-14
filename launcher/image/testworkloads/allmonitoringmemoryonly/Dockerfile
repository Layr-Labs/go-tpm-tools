# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main ../basic
# gcloud builds submit --tag us-west1-docker.pkg.dev/tee-compute-global/cs-integration-test-images/allmonitoringmemory:latest --project tee-compute-global
FROM alpine

COPY main /

LABEL "tee.launch_policy.hardened_monitoring"="MEMORYONLY"
LABEL "tee.launch_policy.debug_monitoring"="MEMORYONLY"

ENTRYPOINT ["/main"]
