package main

import (
	"context"
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
		var err error
		c.ProjectNumber, err = fetchMetadata(ctx, "project/numeric-project-id")
		if err != nil {
			slog.Debug("could not fetch project number from metadata", "error", err)
		}
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
