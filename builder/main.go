// Package main implements a CVM-based build orchestrator that creates verifiable
// custom Confidential Space images.
//
// The orchestrator:
//  1. Fetches launcher binary and its SLSA provenance
//  2. Fetches builder container's SLSA provenance
//  3. Uploads cos-customizer scripts to GCS for Cloud Build
//  4. Triggers Cloud Build to create the GCE image
//  5. Builds manifest binding provenance to output
//  6. Requests GCA attestation with nonce = SHA256(manifest)
//  7. Stores attestation in GCS
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(context.Background()); err != nil {
		slog.Error("build failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	config, err := loadConfig(ctx)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	launcher, err := fetchLauncher(ctx, config)
	if err != nil {
		return fmt.Errorf("fetch launcher: %w", err)
	}

	// Convert docker:// path to image reference for Cloud Build to pull
	launcherImageRef, err := dockerPathToImageRef(config.LauncherArtifact)
	if err != nil {
		return fmt.Errorf("parse launcher artifact: %w", err)
	}

	builder, err := fetchBuilder(ctx, config)
	if err != nil {
		return fmt.Errorf("fetch builder: %w", err)
	}

	// Upload cos-customizer scripts to GCS for Cloud Build to use as source
	// Returns generation number to prevent TOCTOU attacks on the source archive
	sourceGen, err := uploadSource(ctx, config)
	if err != nil {
		return fmt.Errorf("upload source: %w", err)
	}

	build, err := triggerBuild(ctx, config, launcherImageRef, sourceGen)
	if err != nil {
		return fmt.Errorf("trigger build: %w", err)
	}

	// Capture PCR values by booting the image on all CVM platforms
	pcrs, err := capturePCRs(ctx, config)
	if err != nil {
		return fmt.Errorf("capture pcrs: %w", err)
	}

	manifest := newManifest(config, launcher, builder, build, pcrs)

	attestation, err := attest(ctx, config, manifest)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	path, err := storeAttestation(ctx, config, attestation)
	if err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	slog.Info("build complete",
		"image_id", build.ImageID,
		"attestation", path,
	)
	return nil
}

func fetchLauncher(ctx context.Context, config *Config) (*LauncherResult, error) {
	result, err := fetchLauncherWithProvenance(ctx, config)
	if err != nil {
		return nil, err
	}
	if result.Signature == nil {
		return nil, fmt.Errorf("launcher missing provenance signature")
	}

	slog.Info("launcher fetched",
		"binaryDigest", result.BinaryDigest,
		"imageDigest", result.ImageDigest,
	)
	return result, nil
}

func fetchBuilder(ctx context.Context, config *Config) (*BuilderResult, error) {
	result, err := fetchBuilderProvenance(ctx, config)
	if err != nil {
		return nil, err
	}
	if result.Signature == nil {
		return nil, fmt.Errorf("builder missing provenance signature")
	}

	slog.Info("builder fetched", "imageDigest", result.ImageDigest)
	return result, nil
}

func triggerBuild(ctx context.Context, config *Config, launcherPath string, sourceGen int64) (*BuildResult, error) {
	result, err := triggerImageBuild(ctx, config, launcherPath, sourceGen)
	if err != nil {
		return nil, err
	}
	if result.BuildID == "" || result.ImageID == "" {
		return nil, fmt.Errorf("incomplete build result: id=%q image=%q", result.BuildID, result.ImageID)
	}

	slog.Info("build complete",
		"build_id", result.BuildID,
		"image_id", result.ImageID,
		"status", result.Status,
		"duration", result.Duration,
	)
	return result, nil
}

func attest(ctx context.Context, config *Config, manifest Manifest) (*BuildAttestation, error) {
	hash, err := hashJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("hash manifest: %w", err)
	}

	token, err := requestGCAAttestation(ctx, config, hash)
	if err != nil {
		return nil, err
	}

	manifestDigest := "sha256:" + hex.EncodeToString(hash)
	slog.Info("attestation received", "manifestDigest", manifestDigest)

	return &BuildAttestation{
		Manifest:       manifest,
		ManifestDigest: manifestDigest,
		GCAToken:       token,
	}, nil
}
