// Package main implements a CVM-based build orchestrator that creates verifiable
// custom Confidential Space images. It runs on a standard Confidential Space image
// and uses GCA attestation to prove the build inputs.
//
// The orchestrator:
// 1. Fetches launcher binary from Docker image and its SLSA provenance
// 2. Fetches builder container's SLSA provenance (from GCA token)
// 3. Triggers Cloud Build (cos-customizer) to create the GCE image
// 4. Builds manifest with launcher/builder provenance + output info
// 5. Requests GCA attestation with nonce = SHA256(manifest)
// 6. Stores the attestation in GCS for auditors
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config holds the builder configuration from environment variables.
type Config struct {
	// ProjectID is the GCP project for Cloud Build and image output
	ProjectID string

	// ProjectNumber is the numeric project ID (for service account references)
	ProjectNumber string

	// LauncherArtifact is the Docker image containing the launcher binary
	// Format: docker://REGION/PROJECT/REPO/IMAGE/VERSION
	LauncherArtifact string

	// BaseImage is the source COS image name
	BaseImage string

	// BaseImageProject is the project containing the base image
	BaseImageProject string

	// OutputImageName is the name for the output image
	OutputImageName string

	// OutputImageFamily is the image family for the output
	OutputImageFamily string

	// AttestationBucket is the GCS bucket for storing attestations
	AttestationBucket string

	// CloudBuildBucket is the GCS bucket for cos-customizer work
	CloudBuildBucket string

	// GCAEndpoint is the Google Cloud Attestation endpoint
	// Default: https://confidentialcomputing.googleapis.com
	GCAEndpoint string
}

// Manifest is the clean attestation manifest that binds source to output.
type Manifest struct {
	Version      string     `json:"version"`
	Timestamp    time.Time  `json:"timestamp"`
	Source       SourceInfo `json:"source"`
	BaseImage    BaseImage  `json:"base_image"`
	Output       OutputInfo `json:"output"`
	CloudBuildID string     `json:"cloud_build_id"`
}

// SourceInfo contains the launcher and builder with their SLSA provenances.
type SourceInfo struct {
	Launcher LauncherInfo `json:"launcher"`
	Builder  BuilderInfo  `json:"builder"`
}

// LauncherInfo contains the launcher binary hash and its SLSA provenance.
type LauncherInfo struct {
	SHA256     string          `json:"sha256"`
	Provenance json.RawMessage `json:"provenance,omitempty"`
}

// BuilderInfo contains the builder container hash and its SLSA provenance.
type BuilderInfo struct {
	SHA256     string          `json:"sha256"`
	Provenance json.RawMessage `json:"provenance,omitempty"`
}

// BaseImage identifies the source COS image.
type BaseImage struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

// OutputInfo identifies the resulting GCE image.
type OutputInfo struct {
	ImageID   string `json:"image_id"`
	ImageName string `json:"image_name"`
	Project   string `json:"project"`
}

// BuildAttestation is the complete attestation package stored in GCS.
type BuildAttestation struct {
	Manifest     Manifest `json:"manifest"`
	ManifestHash string   `json:"manifest_hash"`
	GCAToken     string   `json:"gca_token"`
}

// LauncherResult contains the launcher binary info and provenance.
type LauncherResult struct {
	SHA256     string
	Data       []byte // The launcher binary data
	Provenance json.RawMessage
}

func main() {
	log("=== Verifiable Image Build Orchestrator ===")

	ctx := context.Background()

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log("ERROR: Failed to load config: %v", err)
		os.Exit(1)
	}
	log("Configuration loaded")
	log("  Project: %s", config.ProjectID)
	log("  Launcher: %s", config.LauncherArtifact)
	log("  Base Image: %s (project: %s)", config.BaseImage, config.BaseImageProject)
	log("  Output: %s (family: %s)", config.OutputImageName, config.OutputImageFamily)

	// Step 1: Fetch launcher and its SLSA provenance
	log("\n=== Step 1: Fetch Launcher Provenance ===")
	launcherResult, err := fetchLauncherWithProvenance(ctx, config)
	if err != nil {
		log("ERROR: Failed to fetch launcher: %v", err)
		os.Exit(1)
	}
	log("Launcher SHA256: %s", launcherResult.SHA256)
	if launcherResult.Provenance != nil {
		log("Launcher SLSA provenance: %d bytes", len(launcherResult.Provenance))
	} else {
		log("WARNING: No launcher SLSA provenance found")
	}

	// Upload the verified launcher to GCS for the Cloud Build step
	launcherGCSPath := fmt.Sprintf("gs://%s/verified-launcher/%s/launcher", config.CloudBuildBucket, launcherResult.SHA256[:16])
	log("Uploading verified launcher to %s...", launcherGCSPath)
	if err := uploadToGCS(ctx, config.CloudBuildBucket, fmt.Sprintf("verified-launcher/%s/launcher", launcherResult.SHA256[:16]), launcherResult.Data); err != nil {
		log("ERROR: Failed to upload launcher to GCS: %v", err)
		os.Exit(1)
	}

	// Step 2: Fetch builder container provenance
	log("\n=== Step 2: Fetch Builder Provenance ===")
	builderResult, err := fetchBuilderProvenance(ctx, config)
	if err != nil {
		log("WARNING: Could not fetch builder provenance: %v", err)
		builderResult = &BuilderResult{SHA256: "unknown"}
	} else {
		log("Builder SHA256: %s", builderResult.SHA256)
		if builderResult.Provenance != nil {
			log("Builder SLSA provenance: %d bytes", len(builderResult.Provenance))
		} else {
			log("WARNING: No builder SLSA provenance found")
		}
	}

	// Step 3: Trigger Cloud Build
	log("\n=== Step 3: Trigger Cloud Build ===")
	buildResult, err := triggerImageBuild(ctx, config, launcherGCSPath)
	if err != nil {
		log("ERROR: Failed to trigger build: %v", err)
		os.Exit(1)
	}
	log("Build completed:")
	log("  Build ID: %s", buildResult.BuildID)
	log("  Image ID: %s", buildResult.ImageID)

	// Step 4: Build manifest
	log("\n=== Step 4: Build Manifest ===")
	manifest := Manifest{
		Version:   "1",
		Timestamp: time.Now().UTC(),
		Source: SourceInfo{
			Launcher: LauncherInfo{
				SHA256:     launcherResult.SHA256,
				Provenance: launcherResult.Provenance,
			},
			Builder: BuilderInfo{
				SHA256:     builderResult.SHA256,
				Provenance: builderResult.Provenance,
			},
		},
		BaseImage: BaseImage{
			Name:    config.BaseImage,
			Project: config.BaseImageProject,
		},
		Output: OutputInfo{
			ImageID:   buildResult.ImageID,
			ImageName: config.OutputImageName,
			Project:   config.ProjectID,
		},
		CloudBuildID: buildResult.BuildID,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		log("ERROR: Failed to marshal manifest: %v", err)
		os.Exit(1)
	}
	manifestHash := sha256.Sum256(manifestJSON)
	manifestHashHex := hex.EncodeToString(manifestHash[:])
	log("Manifest hash (nonce): %s", manifestHashHex)

	// Step 5: Request GCA attestation
	log("\n=== Step 5: Request GCA Attestation ===")
	gcaToken, err := requestGCAAttestation(ctx, config, manifestHash[:])
	if err != nil {
		log("ERROR: Failed to get GCA attestation: %v", err)
		os.Exit(1)
	}
	log("GCA attestation received (%d bytes)", len(gcaToken))

	// Step 6: Store attestation
	log("\n=== Step 6: Store Attestation ===")
	attestation := BuildAttestation{
		Manifest:     manifest,
		ManifestHash: manifestHashHex,
		GCAToken:     gcaToken,
	}

	attestationPath, err := storeAttestation(ctx, config, &attestation)
	if err != nil {
		log("ERROR: Failed to store attestation: %v", err)
		os.Exit(1)
	}
	log("Attestation stored: %s", attestationPath)

	log("\n=== BUILD COMPLETE ===")
	log("Image ID: %s", manifest.Output.ImageID)
	log("Attestation: %s", attestationPath)
	log("")
	log("Verification:")
	log("  1. Verify GCA JWT signature (Google's key)")
	log("  2. Verify JWT.eat_nonce == SHA256(manifest)")
	log("  3. Verify manifest.output.image_id matches your image")
	log("  4. Verify SLSA provenance in manifest.source.slsa_provenance")
	log("  5. Extract commit from provenance → proves image came from that commit")
}

func loadConfig() (*Config, error) {
	config := &Config{
		ProjectID:         os.Getenv("PROJECT_ID"),
		ProjectNumber:     os.Getenv("PROJECT_NUMBER"),
		LauncherArtifact:  os.Getenv("LAUNCHER_ARTIFACT"),
		BaseImage:         os.Getenv("BASE_IMAGE"),
		BaseImageProject:  os.Getenv("BASE_IMAGE_PROJECT"),
		OutputImageName:   os.Getenv("OUTPUT_IMAGE_NAME"),
		OutputImageFamily: os.Getenv("OUTPUT_IMAGE_FAMILY"),
		AttestationBucket: os.Getenv("ATTESTATION_BUCKET"),
		CloudBuildBucket:  os.Getenv("CLOUDBUILD_BUCKET"),
		GCAEndpoint:       os.Getenv("GCA_ENDPOINT"),
	}

	if config.GCAEndpoint == "" {
		config.GCAEndpoint = "https://confidentialcomputing.googleapis.com"
	}

	// Try to get project number from metadata if not provided
	if config.ProjectNumber == "" {
		projectNum, err := getProjectNumberFromMetadata()
		if err != nil {
			log("WARNING: Could not get project number from metadata: %v", err)
		} else {
			config.ProjectNumber = projectNum
		}
	}

	// Validate required fields
	required := map[string]string{
		"PROJECT_ID":         config.ProjectID,
		"LAUNCHER_ARTIFACT":  config.LauncherArtifact,
		"BASE_IMAGE":         config.BaseImage,
		"BASE_IMAGE_PROJECT": config.BaseImageProject,
		"OUTPUT_IMAGE_NAME":  config.OutputImageName,
		"ATTESTATION_BUCKET": config.AttestationBucket,
		"CLOUDBUILD_BUCKET":  config.CloudBuildBucket,
		"PROJECT_NUMBER":     config.ProjectNumber,
	}

	for name, value := range required {
		if value == "" {
			return nil, fmt.Errorf("required environment variable %s not set", name)
		}
	}

	return config, nil
}

func getProjectNumberFromMetadata() (string, error) {
	// Import compute/metadata in imports at top of file
	// For now use a simple HTTP request
	return fetchMetadata("project/numeric-project-id")
}

func fetchMetadata(path string) (string, error) {
	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func log(format string, args ...any) {
	fmt.Printf(time.Now().Format("15:04:05")+" "+format+"\n", args...)
}
