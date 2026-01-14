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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGCAEndpoint  = "https://confidentialcomputing.googleapis.com"
	defaultZone         = "us-central1-a"
	defaultOEMSize      = "500M"
	defaultDiskSizeGB   = 11
	defaultBuildTimeout = 3000
	metadataTimeout     = 5 * time.Second
)

// Config holds builder configuration from environment variables.
type Config struct {
	ProjectID         string
	ProjectNumber     string
	LauncherArtifact  string // docker://REGION/PROJECT/REPO/IMAGE/VERSION
	BaseImage         string
	BaseImageProject  string
	OutputImageName   string
	OutputImageFamily string
	StagingBucket     string // cos-customizer temp files
	ProvenanceBucket  string // attestations
	GCAEndpoint       string
	ImageEnv          string
	Zone              string
	DiskSizeGB        int
	OEMSize           string
	BuildTimeout      int64
}

type Manifest struct {
	Version      string     `json:"version"`
	Timestamp    time.Time  `json:"timestamp"`
	Source       SourceInfo `json:"source"`
	BaseImage    ImageRef   `json:"base_image"`
	Output       ImageRef   `json:"output"`
	CloudBuildID string     `json:"cloud_build_id"`
}

type SourceInfo struct {
	Launcher ArtifactInfo `json:"launcher"`
	Builder  ArtifactInfo `json:"builder"`
}

type ArtifactInfo struct {
	SHA256        string               `json:"sha256"`
	ImageDigest   string               `json:"image_digest,omitempty"`
	ProvenanceRef string               `json:"provenance_ref"`
	Signature     *ProvenanceSignature `json:"signature,omitempty"`
}

type ProvenanceSignature struct {
	KeyID     string `json:"keyid,omitempty"`
	Signature string `json:"sig"`
}

type ImageRef struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Project string `json:"project"`
}

type BuildAttestation struct {
	Manifest     Manifest `json:"manifest"`
	ManifestHash string   `json:"manifest_hash"`
	GCAToken     string   `json:"gca_token"`
}

type LauncherResult struct {
	SHA256        string
	ImageDigest   string
	ProvenanceRef string
	Signature     *ProvenanceSignature
	Data          []byte
}

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

	manifest := newManifest(config, launcher, builder, build)

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

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

func loadConfig(ctx context.Context) (*Config, error) {
	c := &Config{
		ProjectID:         os.Getenv("PROJECT_ID"),
		ProjectNumber:     os.Getenv("PROJECT_NUMBER"),
		LauncherArtifact:  os.Getenv("LAUNCHER_ARTIFACT"),
		BaseImage:         os.Getenv("BASE_IMAGE"),
		BaseImageProject:  os.Getenv("BASE_IMAGE_PROJECT"),
		OutputImageName:   os.Getenv("OUTPUT_IMAGE_NAME"),
		OutputImageFamily: os.Getenv("OUTPUT_IMAGE_FAMILY"),
		StagingBucket:     os.Getenv("STAGING_BUCKET"),
		ProvenanceBucket:  os.Getenv("PROVENANCE_BUCKET"),
		GCAEndpoint:       envOr("GCA_ENDPOINT", defaultGCAEndpoint),
		ImageEnv:          os.Getenv("IMAGE_ENV"),
		Zone:              envOr("ZONE", defaultZone),
		OEMSize:           envOr("OEM_SIZE", defaultOEMSize),
	}

	var err error
	c.DiskSizeGB, err = envInt("DISK_SIZE_GB", defaultDiskSizeGB)
	if err != nil {
		return nil, err
	}
	c.BuildTimeout, err = envInt64("BUILD_TIMEOUT_SECONDS", defaultBuildTimeout)
	if err != nil {
		return nil, err
	}

	if c.ImageEnv != "debug" && c.ImageEnv != "hardened" {
		return nil, fmt.Errorf("IMAGE_ENV must be debug or hardened, got %q", c.ImageEnv)
	}

	if c.ProjectNumber == "" {
		c.ProjectNumber, _ = fetchMetadata(ctx, "project/numeric-project-id")
	}

	if err := requireEnv(c); err != nil {
		return nil, err
	}

	slog.Info("config loaded",
		"project", c.ProjectID,
		"image_env", c.ImageEnv,
		"output", c.OutputImageName,
	)
	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envInt64(key string, fallback int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// dockerPathToImageRef converts a docker:// path to a container image reference.
// Path format: docker://REGION/PROJECT/REPO/IMAGE/VERSION
// Returns: REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:VERSION
func dockerPathToImageRef(dockerPath string) (string, error) {
	if !strings.HasPrefix(dockerPath, "docker://") {
		return "", fmt.Errorf("invalid docker path: expected docker:// prefix, got %s", dockerPath)
	}

	path := strings.TrimPrefix(dockerPath, "docker://")
	parts := strings.Split(path, "/")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid docker path: expected docker://REGION/PROJECT/REPO/IMAGE/VERSION, got %s", dockerPath)
	}

	region, project, repo, image, version := parts[0], parts[1], parts[2], parts[3], parts[4]
	return fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s:%s", region, project, repo, image, version), nil
}

func requireEnv(c *Config) error {
	missing := ""
	check := func(name, val string) {
		if val == "" {
			if missing != "" {
				missing += ", "
			}
			missing += name
		}
	}

	check("PROJECT_ID", c.ProjectID)
	check("PROJECT_NUMBER", c.ProjectNumber)
	check("LAUNCHER_ARTIFACT", c.LauncherArtifact)
	check("BASE_IMAGE", c.BaseImage)
	check("BASE_IMAGE_PROJECT", c.BaseImageProject)
	check("OUTPUT_IMAGE_NAME", c.OutputImageName)
	check("STAGING_BUCKET", c.StagingBucket)
	check("PROVENANCE_BUCKET", c.ProvenanceBucket)

	if missing != "" {
		return fmt.Errorf("missing required env: %s", missing)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Build Steps
// -----------------------------------------------------------------------------

func fetchLauncher(ctx context.Context, config *Config) (*LauncherResult, error) {
	result, err := fetchLauncherWithProvenance(ctx, config)
	if err != nil {
		return nil, err
	}
	if result.Signature == nil {
		return nil, fmt.Errorf("launcher missing provenance signature")
	}

	slog.Info("launcher fetched",
		"sha256", result.SHA256,
		"digest", result.ImageDigest,
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

	slog.Info("builder fetched", "sha256", result.SHA256)
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

	slog.Info("attestation received", "manifest_hash", hex.EncodeToString(hash))

	return &BuildAttestation{
		Manifest:     manifest,
		ManifestHash: hex.EncodeToString(hash),
		GCAToken:     token,
	}, nil
}

// -----------------------------------------------------------------------------
// Manifest
// -----------------------------------------------------------------------------

func newManifest(config *Config, launcher *LauncherResult, builder *BuilderResult, build *BuildResult) Manifest {
	return Manifest{
		Version:   "1",
		Timestamp: time.Now().UTC(),
		Source: SourceInfo{
			Launcher: ArtifactInfo{
				SHA256:        launcher.SHA256,
				ImageDigest:   launcher.ImageDigest,
				ProvenanceRef: launcher.ProvenanceRef,
				Signature:     launcher.Signature,
			},
			Builder: ArtifactInfo{
				SHA256:        builder.SHA256,
				ProvenanceRef: builder.ProvenanceRef,
				Signature:     builder.Signature,
			},
		},
		BaseImage: ImageRef{
			Name:    config.BaseImage,
			Project: config.BaseImageProject,
		},
		Output: ImageRef{
			Name:    config.OutputImageName,
			ID:      build.ImageID,
			Project: config.ProjectID,
		},
		CloudBuildID: build.BuildID,
	}
}

func hashJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// -----------------------------------------------------------------------------
// Metadata
// -----------------------------------------------------------------------------

func fetchMetadata(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()

	url := "http://metadata.google.internal/computeMetadata/v1/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	return string(body), nil
}
