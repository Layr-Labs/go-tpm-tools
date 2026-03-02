# From current directory:
# gcloud builds submit --tag us-central1-docker.pkg.dev/tee-compute-global/cs-test/privileged:latest --project tee-compute-global
FROM alpine

RUN apk update
RUN apk add libcap

LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_capabilities"="true"
LABEL "tee.launch_policy.allow_cgroups"="true"

# Get capabilities for PID 1.
# Run the 'ls' command on /sys/fs/cgroup and attempt to create a new cgroup.
ENTRYPOINT ["sh", "-c", "getpcaps 1 && ls -la /sys/fs/cgroup && cd /sys/fs/cgroup && mkdir -p cpu/testgroup && mkdir -p memory/testgroup && ls cpu"]
