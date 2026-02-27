package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
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

// pcrCaptureResult matches the JSON output from the pcr-capture workload.
type pcrCaptureResult struct {
	Platform string            `json:"platform"`
	PCRs     map[string]string `json:"pcrs"`
}

// capturePCRs boots the output image on all CVM platforms and collects PCR values.
func capturePCRs(ctx context.Context, config *Config) (map[string]PlatformPCRs, error) {
	specs := []platformSpec{
		{
			Name:             "intel_tdx",
			MachineType:      "c3-standard-4",
			Zone:             config.Zone,
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
			MachineType:      "n2d-standard-2",
			Zone:             config.SEVZone,
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
			pcrs, err := capturePlatformPCRs(ctx, config, computeSvc, storageSvc, s)
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

// capturePlatformPCRs creates a VM, waits for PCR results in GCS, and cleans up.
func capturePlatformPCRs(ctx context.Context, config *Config, computeSvc *compute.Service, storageSvc *storage.Client, spec platformSpec) (PlatformPCRs, error) {
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

	instance := buildCaptureInstance(config, spec, instanceName, gcsURI)

	if _, err := computeSvc.Instances.Insert(config.ProjectID, spec.Zone, instance).Context(ctx).Do(); err != nil {
		return PlatformPCRs{}, fmt.Errorf("create VM: %w", err)
	}

	// Poll GCS for the result file.
	bucket := storageSvc.Bucket(config.ProvenanceBucket)
	result, err := pollForPCRResult(ctx, bucket, gcsPath, spec)
	if err != nil {
		return PlatformPCRs{}, err
	}

	return PlatformPCRs{
		PCR4: result.PCRs["4"],
		PCR8: result.PCRs["8"],
		PCR9: result.PCRs["9"],
	}, nil
}

// buildCaptureInstance creates the Compute Engine instance spec for a PCR capture VM.
func buildCaptureInstance(config *Config, spec platformSpec, instanceName, gcsURI string) *compute.Instance {
	metadata := []*compute.MetadataItems{
		{Key: "tee-image-reference", Value: strPtr(config.PCRCaptureImage)},
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
		Scheduling: &compute.Scheduling{
			OnHostMaintenance: "TERMINATE",
		},
		ShieldedInstanceConfig: &compute.ShieldedInstanceConfig{
			EnableSecureBoot: true,
		},
	}

	if spec.ConfidentialType != "" {
		instance.ConfidentialInstanceConfig = &compute.ConfidentialInstanceConfig{
			ConfidentialInstanceType: spec.ConfidentialType,
		}
	}

	return instance
}

// pollForPCRResult polls GCS until the PCR result file appears or timeout.
func pollForPCRResult(ctx context.Context, bucket *storage.BucketHandle, gcsPath string, spec platformSpec) (*pcrCaptureResult, error) {
	deadline := time.Now().Add(pcrCaptureTimeout)

	for time.Now().Before(deadline) {
		reader, err := bucket.Object(gcsPath).NewReader(ctx)
		if err == nil {
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				return nil, fmt.Errorf("read GCS result: %w", err)
			}

			var result pcrCaptureResult
			if err := json.Unmarshal(data, &result); err != nil {
				return nil, fmt.Errorf("parse PCR result: %w", err)
			}

			// Validate the result has the expected PCR indices.
			for _, idx := range []string{"4", "8", "9"} {
				if result.PCRs[idx] == "" {
					return nil, fmt.Errorf("PCR %s missing from %s result", idx, spec.Name)
				}
			}

			return &result, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pcrCapturePollRate):
		}
	}

	return nil, fmt.Errorf("timeout waiting for PCR capture result from %s after %v", spec.Name, pcrCaptureTimeout)
}

func strPtr(s string) *string {
	return &s
}
