package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	sdkattest "github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	compute "google.golang.org/api/compute/v1"
)

const (
	pcrCaptureTimeout  = 10 * time.Minute
	pcrCapturePollRate = 15 * time.Second
)

// platformSpec defines the VM configuration for a CVM platform.
type platformSpec struct {
	Name             string
	MachineType      string
	Zone             string
	ConfidentialType string // empty for Shielded VM
}

// attestationEvidence wraps the raw attestation and challenge from pcr-capture.
type attestationEvidence struct {
	Challenge   string `json:"challenge"`   // base64-encoded nonce
	Attestation string `json:"attestation"` // base64-encoded attestation proto
}

// capturePCRs boots the output image on all CVM platforms and collects PCR values.
// pcrCaptureImage should be pinned by digest (e.g., "registry/image@sha256:...").
// pcrCaptureImageDigest is the expected container image digest (e.g., "sha256:abc...") for attestation verification.
func capturePCRs(ctx context.Context, config *Config, pcrCaptureImage, pcrCaptureImageDigest string) (map[string]PlatformPCRs, error) {
	specs := []platformSpec{
		{
			Name:             "intel_tdx",
			MachineType:      "c3-standard-4",
			Zone:             config.TDXZone,
			ConfidentialType: "TDX",
		},
		{
			Name:             "amd_sev_snp",
			MachineType:      "n2d-standard-2",
			Zone:             config.SEVZone,
			ConfidentialType: "SEV_SNP",
		},
		{
			Name:             "gcp_shielded_vm",
			MachineType:      "e2-medium",
			Zone:             config.Zone,
			ConfidentialType: "", // no confidential compute for shielded
		},
	}

	computeSvc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("create compute service: %w", err)
	}

	storageSvc, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer storageSvc.Close()

	// Launch all capture VMs in parallel.
	type captureResult struct {
		spec platformSpec
		pcrs PlatformPCRs
		err  error
	}
	results := make(chan captureResult, len(specs))

	var wg sync.WaitGroup
	for _, spec := range specs {
		wg.Add(1)
		go func(s platformSpec) {
			defer wg.Done()
			pcrs, err := capturePlatformPCRs(ctx, config, pcrCaptureImage, pcrCaptureImageDigest, computeSvc, storageSvc, s)
			results <- captureResult{spec: s, pcrs: pcrs, err: err}
		}(spec)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	allPCRs := make(map[string]PlatformPCRs, len(specs))
	var errs []string
	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.spec.Name, r.err))
			continue
		}
		allPCRs[r.spec.Name] = r.pcrs
		slog.Info("captured PCRs",
			"platform", r.spec.Name,
			"pcr4", r.pcrs.PCR4,
			"pcr8", r.pcrs.PCR8,
			"pcr9", r.pcrs.PCR9,
		)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("PCR capture failed:\n  %s", strings.Join(errs, "\n  "))
	}

	return allPCRs, nil
}

// capturePlatformPCRs creates a VM, waits for attestation evidence in GCS, verifies it, and cleans up.
func capturePlatformPCRs(ctx context.Context, config *Config, pcrCaptureImage, pcrCaptureImageDigest string, computeSvc *compute.Service, storageSvc *storage.Client, spec platformSpec) (PlatformPCRs, error) {
	instanceName := fmt.Sprintf("pcr-capture-%s-%s", config.OutputImageName, spec.Name)
	// GCE instance names must be <= 63 chars, lowercase, no underscores
	instanceName = strings.ReplaceAll(instanceName, "_", "-")
	if len(instanceName) > 63 {
		instanceName = instanceName[:63]
	}

	gcsPath := fmt.Sprintf("%s/pcr_%s.json", config.OutputImageName, spec.Name)
	gcsURI := fmt.Sprintf("gs://%s/%s", config.ProvenanceBucket, gcsPath)

	slog.Info("launching PCR capture VM",
		"platform", spec.Name,
		"instance", instanceName,
		"zone", spec.Zone,
		"gcs_output", gcsURI,
	)

	// Ensure cleanup regardless of outcome.
	defer func() {
		slog.Info("deleting PCR capture VM", "instance", instanceName, "zone", spec.Zone)
		if _, err := computeSvc.Instances.Delete(config.ProjectID, spec.Zone, instanceName).Context(ctx).Do(); err != nil {
			slog.Warn("failed to delete PCR capture VM", "instance", instanceName, "error", err)
		}
	}()

	instance := buildCaptureInstance(config, pcrCaptureImage, spec, instanceName, gcsURI)

	op, err := computeSvc.Instances.Insert(config.ProjectID, spec.Zone, instance).Context(ctx).Do()
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("create VM: %w", err)
	}
	if op.TargetId == 0 {
		return PlatformPCRs{}, fmt.Errorf("instance insert returned zero TargetId")
	}
	slog.Info("PCR capture VM created",
		"platform", spec.Name,
		"instanceID", op.TargetId,
	)

	// Poll GCS for the attestation evidence file.
	bucket := storageSvc.Bucket(config.ProvenanceBucket)
	attestPath := fmt.Sprintf("%s/pcr_%s.attestation.json", config.OutputImageName, spec.Name)
	evidence, err := pollForAttestation(ctx, bucket, attestPath, spec)
	if err != nil {
		return PlatformPCRs{}, err
	}

	// Verify attestation and extract PCRs.
	pcrs, err := verifyPCRAttestation(evidence, op.TargetId, pcrCaptureImageDigest)
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("verify attestation: %w", err)
	}

	return pcrs, nil
}

// buildCaptureInstance creates the Compute Engine instance spec for a PCR capture VM.
func buildCaptureInstance(config *Config, pcrCaptureImage string, spec platformSpec, instanceName, gcsURI string) *compute.Instance {
	metadata := []*compute.MetadataItems{
		{Key: "tee-image-reference", Value: strPtr(pcrCaptureImage)},
		{Key: "tee-restart-policy", Value: strPtr("Never")},
		{Key: "tee-container-log-redirect", Value: strPtr("true")},
		{Key: "tee-env-GCS_OUTPUT", Value: strPtr(gcsURI)},
		{Key: "self-verification", Value: strPtr("true")},
	}

	instance := &compute.Instance{
		Name:        instanceName,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/%s", spec.Zone, spec.MachineType),
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: fmt.Sprintf("projects/%s/global/images/%s", config.ProjectID, config.OutputImageName),
					DiskSizeGb:  30,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					{Type: "ONE_TO_ONE_NAT"},
				},
			},
		},
		Metadata: &compute.Metadata{
			Items: metadata,
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email:  "default",
				Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		},
		ShieldedInstanceConfig: &compute.ShieldedInstanceConfig{
			EnableSecureBoot: true,
		},
	}

	if spec.ConfidentialType != "" {
		instance.ConfidentialInstanceConfig = &compute.ConfidentialInstanceConfig{
			ConfidentialInstanceType: spec.ConfidentialType,
		}
		instance.Scheduling = &compute.Scheduling{
			OnHostMaintenance: "TERMINATE",
		}
	}

	return instance
}

// pollForAttestation polls GCS until the attestation evidence file appears or timeout.
func pollForAttestation(ctx context.Context, bucket *storage.BucketHandle, gcsPath string, spec platformSpec) (*attestationEvidence, error) {
	deadline := time.Now().Add(pcrCaptureTimeout)

	for time.Now().Before(deadline) {
		reader, err := bucket.Object(gcsPath).NewReader(ctx)
		if err == nil {
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				return nil, fmt.Errorf("read GCS attestation: %w", err)
			}

			var evidence attestationEvidence
			if err := json.Unmarshal(data, &evidence); err != nil {
				return nil, fmt.Errorf("parse attestation evidence: %w", err)
			}
			if evidence.Challenge == "" || evidence.Attestation == "" {
				return nil, fmt.Errorf("incomplete attestation evidence from %s", spec.Name)
			}

			return &evidence, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pcrCapturePollRate):
		}
	}

	return nil, fmt.Errorf("timeout waiting for attestation from %s after %v", spec.Name, pcrCaptureTimeout)
}

// verifyPCRAttestation verifies the TPM+TEE attestation from a pcr-capture VM
// and extracts verified PCR values.
func verifyPCRAttestation(evidence *attestationEvidence, expectedInstanceID uint64, expectedImageDigest string) (PlatformPCRs, error) {
	challenge, err := base64.StdEncoding.DecodeString(evidence.Challenge)
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("decode challenge: %w", err)
	}
	attestBytes, err := base64.StdEncoding.DecodeString(evidence.Attestation)
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("decode attestation: %w", err)
	}

	att, err := sdkattest.Parse(attestBytes)
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("parse attestation: %w", err)
	}

	// Verify TPM quote.
	tpmResult, err := att.VerifyTPM(challenge, nil)
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("verify TPM: %w", err)
	}

	// Verify TEE binding (TDX/SEV-SNP). Shielded VM has no TEE layer.
	if _, err := att.VerifyBoundTEE(challenge, nil); err != nil {
		if att.Platform() != sdkattest.PlatformGCPShieldedVM {
			return PlatformPCRs{}, fmt.Errorf("verify TEE: %w", err)
		}
	}

	// Extract verified TPM claims with requested PCR indices.
	claims, err := tpmResult.ExtractTPMClaims(sdkattest.ExtractOptions{
		PCRIndices: []uint32{4, 8, 9},
	})
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("extract TPM claims: %w", err)
	}

	// Verify instance ID matches the VM the builder launched.
	if claims.GCE == nil {
		return PlatformPCRs{}, fmt.Errorf("no GCE info in attestation")
	}
	if claims.GCE.InstanceID != expectedInstanceID {
		return PlatformPCRs{}, fmt.Errorf("instance ID mismatch: attestation=%d, expected=%d", claims.GCE.InstanceID, expectedInstanceID)
	}

	// Verify the pcr-capture container image digest.
	container, err := att.ExtractContainerClaims()
	if err != nil {
		return PlatformPCRs{}, fmt.Errorf("extract container claims: %w", err)
	}
	if container.ImageDigest != expectedImageDigest {
		return PlatformPCRs{}, fmt.Errorf("container image digest mismatch: attestation=%q, expected=%q", container.ImageDigest, expectedImageDigest)
	}

	pcr4 := claims.PCRs[4]
	pcr8 := claims.PCRs[8]
	pcr9 := claims.PCRs[9]
	return PlatformPCRs{
		PCR4: hex.EncodeToString(pcr4[:]),
		PCR8: hex.EncodeToString(pcr8[:]),
		PCR9: hex.EncodeToString(pcr9[:]),
	}, nil
}

func strPtr(s string) *string {
	return &s
}
