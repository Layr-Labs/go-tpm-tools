#!/usr/bin/env fish
#
# E2E test for the PD auto-grow feature on sepolia-prod.
#
# Prereqs:
#   - ecloud CLI installed
#   - ECLOUD_PRIVATE_KEY env var set, or key file at
#     ~/.config/ecloud/keys/sepolia-prod.key (chmod 600)
#   - gcloud authenticated for tee-compute-sepolia-prod
#   - A launcher image built from branch mb/pd-auto-grow and published
#
# Run manually, step-by-step, reading the output between phases. This
# script doesn't try to be fully autonomous — some steps (inspecting
# logs, confirming app health) benefit from a human in the loop.

set -l KEY_FILE ~/.config/ecloud/keys/sepolia-prod.key
if not set -q ECLOUD_PRIVATE_KEY
    if test -f $KEY_FILE
        set -x ECLOUD_PRIVATE_KEY (cat $KEY_FILE)
    else
        echo "ERROR: set ECLOUD_PRIVATE_KEY or place key in $KEY_FILE"
        exit 1
    end
end

set -l APP_NAME pd-auto-grow-e2e-(date +%s)
set -l PROJECT tee-compute-sepolia-prod

echo "=== Step 1: Deploy minimal test app with 10 GB PD ==="
echo "App name: $APP_NAME"
echo "Project: $PROJECT"
echo ""
echo "Run (example — adapt to your test app image):"
echo "  ecloud compute app deploy \\"
echo "    --environment sepolia-prod \\"
echo "    --name $APP_NAME \\"
echo "    --image <YOUR_TEST_IMAGE> \\"
echo "    --instance-type g1-standard-2t \\"
echo "    --env PERSIST_SIZE_GB=10 \\"
echo "    --force"
echo ""
echo "Press enter once deploy completes..."
read _

echo "=== Step 2: Baseline size log ==="
echo "Within ~90s the launcher should emit its first 'disk sizes' log line."
echo ""
echo "Run:"
echo "  ecloud compute app logs $APP_NAME --tail 200 | grep -E 'pd_size_bytes|mapper_size_bytes|fs_size_bytes'"
echo ""
echo "Expected: one log line per poll tick, all four keys present with"
echo "pd_size_bytes ≈ 10 GiB."
echo ""
echo "Press enter once baseline is confirmed..."
read _

echo "=== Step 3: Write ~5 GB of test data ==="
echo ""
echo "Depends on the test app's write mechanism. Record checksums or"
echo "file counts so you can verify integrity after the grow."
echo ""
echo "Press enter once data is written and checksums recorded..."
read _

echo "=== Step 4: Grow the PD to 20 GB (online, no restart) ==="
echo ""
echo "First discover the VM + zone for $APP_NAME:"
echo "  set -l VM_NAME (ecloud compute app info $APP_NAME --json | jq -r '.vm_name')"
echo "  set -l ZONE (gcloud compute instances list --project=$PROJECT --filter=\"name=\$VM_NAME\" --format=\"value(zone)\")"
echo ""
echo "Then run:"
echo "  gcloud compute disks resize persistent_storage_1 \\"
echo "    --project=$PROJECT \\"
echo "    --zone=\$ZONE \\"
echo "    --size=20GB \\"
echo "    --quiet"
echo ""
echo "Capture the timestamp — you'll compare it against the launcher log timeline."
echo ""
echo "Press enter once the resize command returns..."
read _

echo "=== Step 5: Observe auto-grow (within ~90s) ==="
echo ""
echo "Watch the launcher logs:"
echo "  ecloud compute app logs $APP_NAME --watch | grep -E 'grow|pd_size_bytes|cryptsetup|resize2fs'"
echo ""
echo "Expected sequence within ~90s of Step 4:"
echo "  - 'grow: pd is larger than mapper, resizing'"
echo "  - 'disk sizes' with pd_size_bytes ≈ 20 GiB (all 4 keys in sync)"
echo ""
echo "Press enter once you've observed the grow and confirmed sizes..."
read _

echo "=== Step 6: Verify app uptime / no disconnect ==="
echo ""
echo "Confirm the app stayed healthy across the resize window:"
echo "  ecloud compute app info $APP_NAME"
echo ""
echo "Check any app-level health indicators (container uptime, client"
echo "connections, etc.). Record the window Step 4 timestamp → Step 5"
echo "completion for the PR write-up."
echo ""
echo "Press enter once health is confirmed..."
read _

echo "=== Step 7: Verify data integrity ==="
echo ""
echo "Read back the data written in Step 3. Recompute checksums; they"
echo "must match exactly."
echo ""
echo "Press enter once integrity is confirmed..."
read _

echo "=== Step 8: Second grow (20GB -> 40GB) ==="
echo ""
echo "  gcloud compute disks resize persistent_storage_1 \\"
echo "    --project=$PROJECT \\"
echo "    --zone=\$ZONE \\"
echo "    --size=40GB \\"
echo "    --quiet"
echo ""
echo "Repeat the observe + health + integrity checks from Steps 5-7."
echo ""
echo "Press enter once the second grow is confirmed..."
read _

echo "=== Step 9: Teardown ==="
echo ""
read -P "Terminate app $APP_NAME? [y/N] " confirm
if test "$confirm" = "y"
    echo "Run: ecloud compute app terminate $APP_NAME --force"
else
    echo "Leaving $APP_NAME running; remember to clean up later."
end

echo ""
echo "=== E2E complete. Evidence to capture for the PR ==="
echo "  - Datadog link showing pd_size_bytes timeline across Steps 2, 5, 8"
echo "  - gcloud disks resize output for Steps 4 and 8 (with timestamps)"
echo "  - Launcher log excerpts for boot + both grows"
echo "  - App health confirmation across both resize windows"
echo "  - Data integrity verification output"
