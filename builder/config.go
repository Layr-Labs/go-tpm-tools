package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

const (
	defaultGCAEndpoint  = "https://confidentialcomputing.googleapis.com"
	defaultZone         = "us-central1-a"
	defaultOEMSize      = "500M"
	defaultDiskSizeGB   = 11
	defaultBuildTimeout = 3000
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
	TDXZone           string // Zone for TDX platforms (default: same as Zone)
	SEVZone           string // Zone for SEV-SNP/Shielded VM platforms (default: same as Zone)
	DiskSizeGB        int
	OEMSize           string
	BuildTimeout      int64
	PCRCaptureImage   string // e.g. "us-central1-docker.pkg.dev/proj/cs-build/pcr-capture:v0.1.0"
}

func loadConfig(ctx context.Context) (*Config, error) {
	zone := envOr("ZONE", defaultZone)
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
		Zone:              zone,
		OEMSize:           envOr("OEM_SIZE", defaultOEMSize),
		PCRCaptureImage:   os.Getenv("PCR_CAPTURE_IMAGE"),
		TDXZone:           envOr("TDX_ZONE", zone),
		SEVZone:           envOr("SEV_ZONE", zone),
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
	check("PCR_CAPTURE_IMAGE", c.PCRCaptureImage)

	if missing != "" {
		return fmt.Errorf("missing required env: %s", missing)
	}
	return nil
}
