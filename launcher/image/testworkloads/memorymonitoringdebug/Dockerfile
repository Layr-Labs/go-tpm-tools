# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main ../basic
# gcloud builds submit --tag us-central1-docker.pkg.dev/tee-compute-global/cs-test/memorymonitoringdebug:latest --project tee-compute-global
FROM alpine

COPY main /

ENV env_bar="val_bar"

LABEL "tee.launch_policy.monitoring_memory_allow"="debugonly"

ENTRYPOINT ["/main"]

CMD ["arg_foo"]
