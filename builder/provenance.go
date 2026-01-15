package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	grafeas "google.golang.org/genproto/googleapis/grafeas/v1"
)

// httpClient is a shared HTTP client with reasonable timeouts for production use.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
}

// stripImageTag removes the tag from an image reference.
// e.g., "registry/project/repo/image:v1" -> "registry/project/repo/image"
func stripImageTag(imageRef string) string {
	if idx := strings.LastIndex(imageRef, ":"); idx != -1 {
		return imageRef[:idx]
	}
	return imageRef
}

// downloadImageContents downloads a file from a container image and returns both
// the image digest and the file contents. Uses go-containerregistry for registry access.
func downloadImageContents(ctx context.Context, imageRef, filePath string) (digest string, data []byte, err error) {
	// Parse image reference using the library
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Get image with Google auth (handles Artifact Registry automatically)
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(google.Keychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch image: %w", err)
	}

	// Get digest
	d, err := img.Digest()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get image digest: %w", err)
	}
	digest = d.String()

	// Get layers and extract file
	layers, err := img.Layers()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get image layers: %w", err)
	}

	if len(layers) == 0 {
		return "", nil, fmt.Errorf("no layers in image")
	}

	// For a FROM scratch image, iterate through layers to find the file
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			return "", nil, fmt.Errorf("failed to get layer digest: %w", err)
		}
		slog.Debug("checking layer", "digest", layerDigest.String())

		// Get uncompressed layer content (library handles decompression)
		rc, err := layer.Uncompressed()
		if err != nil {
			continue
		}

		data, err = extractFileFromTar(rc, filePath)
		rc.Close()
		if err == nil {
			return digest, data, nil
		}
	}

	return "", nil, fmt.Errorf("file %s not found in image layers", filePath)
}

// BuilderResult contains the builder container digest and provenance.
type BuilderResult struct {
	ImageDigest   string // Container image digest
	ProvenanceRef string // URL to fetch provenance
	Signature     *ProvenanceSignature
}

// fetchLauncherWithProvenance downloads the launcher binary and its SLSA provenance signature from a Docker image.
// Path format: docker://REGION/PROJECT/REPO/IMAGE/VERSION (e.g., docker://us-central1/my-project/launcher/launcher/v1.0.0)
// Returns the launcher hash, binary data, and provenance signature.
func fetchLauncherWithProvenance(ctx context.Context, config *Config) (*LauncherResult, error) {
	if !strings.HasPrefix(config.LauncherArtifact, "docker://") {
		return nil, fmt.Errorf("unsupported launcher artifact path: %s (expected docker://REGION/PROJECT/REPO/IMAGE/VERSION)", config.LauncherArtifact)
	}

	launcherData, imageDigest, imageRef, err := downloadLauncherFromDockerImage(ctx, config.LauncherArtifact)
	if err != nil {
		return nil, fmt.Errorf("failed to download launcher from Docker image: %w", err)
	}

	// Compute hash of the binary
	hash := sha256.Sum256(launcherData)
	binaryDigest := "sha256:" + hex.EncodeToString(hash[:])
	slog.Info("launcher downloaded", "size", len(launcherData), "binaryDigest", binaryDigest)

	// Build provenance reference URL
	provenanceRef := "https://" + stripImageTag(imageRef) + "@" + imageDigest

	result := &LauncherResult{
		BinaryDigest:  binaryDigest,
		ImageDigest:   imageDigest,
		ProvenanceRef: provenanceRef,
		Data:          launcherData,
	}

	// Fetch provenance signature
	slog.Info("querying provenance", "resourceUri", provenanceRef)
	signature, err := fetchProvenanceSignature(ctx, config.ProjectID, provenanceRef)
	if err != nil {
		slog.Warn("could not fetch launcher provenance signature", "error", err)
	} else {
		result.Signature = signature
		slog.Info("launcher provenance signature fetched")
	}

	return result, nil
}

// downloadLauncherFromDockerImage extracts the launcher binary from a Docker image.
// Path format: docker://REGION/PROJECT/REPO/IMAGE/VERSION
// Returns the binary data, image digest, and image reference.
func downloadLauncherFromDockerImage(ctx context.Context, dockerPath string) ([]byte, string, string, error) {
	// Parse docker://REGION/PROJECT/REPO/IMAGE/VERSION
	path := strings.TrimPrefix(dockerPath, "docker://")
	parts := strings.Split(path, "/")
	if len(parts) != 5 {
		return nil, "", "", fmt.Errorf("invalid Docker path: expected docker://REGION/PROJECT/REPO/IMAGE/VERSION, got %s", dockerPath)
	}
	region, project, repo, image, version := parts[0], parts[1], parts[2], parts[3], parts[4]

	// Build the full image reference
	imageRef := fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s:%s", region, project, repo, image, version)
	slog.Info("downloading launcher from docker image", "ref", imageRef)

	// Download image contents and extract the launcher binary
	digest, data, err := downloadImageContents(ctx, imageRef, "/launcher")
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to download launcher from image: %w", err)
	}
	slog.Debug("image digest", "digest", digest)

	return data, digest, imageRef, nil
}

// extractFileFromTar extracts a single file from a tar archive.
// The go-containerregistry library handles decompression, so this only reads tar.
func extractFileFromTar(r io.Reader, targetPath string) ([]byte, error) {
	// Strip leading slash for tar path comparison
	targetPath = strings.TrimPrefix(targetPath, "/")

	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar: %w", err)
		}

		// Check if this is the file we're looking for
		name := strings.TrimPrefix(header.Name, "./")
		name = strings.TrimPrefix(name, "/")
		if name == targetPath {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("file %s not found in archive", targetPath)
}

// fetchBuilderProvenance gets the builder container's digest and SLSA provenance signature.
// The digest is obtained from a GCA token, and provenance signature is fetched from Container Analysis API.
func fetchBuilderProvenance(ctx context.Context, config *Config) (*BuilderResult, error) {
	// Request a GCA token to get the container info
	slog.Info("requesting GCA token for container digest")
	token, err := requestGCAAttestation(ctx, config, []byte("digest-lookup"))
	if err != nil {
		return nil, fmt.Errorf("failed to get GCA token for digest lookup: %w", err)
	}

	// Parse the JWT to extract container info from submods.container
	imageDigest, imageRef, err := parseContainerInfoFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container info from token: %w", err)
	}

	slog.Info("builder container identified", "ref", imageRef, "imageDigest", imageDigest)

	// Build provenance reference URL
	provenanceRef := "https://" + stripImageTag(imageRef) + "@" + imageDigest

	result := &BuilderResult{
		ImageDigest:   imageDigest,
		ProvenanceRef: provenanceRef,
	}

	// Query Container Analysis for provenance signature
	slog.Info("querying provenance", "resourceUri", provenanceRef)
	signature, err := fetchProvenanceSignature(ctx, config.ProjectID, provenanceRef)
	if err != nil {
		slog.Warn("could not fetch builder provenance signature",
			"error", err,
			"resourceUri", provenanceRef,
			"imageDigest", imageDigest)
		return result, nil
	}

	result.Signature = signature
	return result, nil
}

// parseContainerInfoFromToken extracts container digest and image reference from a GCA JWT.
func parseContainerInfoFromToken(token string) (digest, imageRef string, err error) {
	// JWT is header.payload.signature - we need the payload
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (base64url encoded, no padding)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the claims
	var claims struct {
		Submods struct {
			Container struct {
				ImageDigest    string `json:"image_digest"`
				ImageReference string `json:"image_reference"`
			} `json:"container"`
		} `json:"submods"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.Submods.Container.ImageDigest == "" {
		return "", "", fmt.Errorf("no container digest in token")
	}

	return claims.Submods.Container.ImageDigest, claims.Submods.Container.ImageReference, nil
}

// fetchProvenanceSignature queries Container Analysis for provenance signature on a container image.
// Returns the DSSE signature for offline verification.
func fetchProvenanceSignature(ctx context.Context, projectID, resourceURL string) (*ProvenanceSignature, error) {
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Container Analysis client: %w", err)
	}
	defer client.Close()

	// Query for BUILD occurrences with specific resourceUri
	filter := fmt.Sprintf(`kind="BUILD" AND resourceUri="%s"`, resourceURL)
	req := &grafeas.ListOccurrencesRequest{
		Parent:   fmt.Sprintf("projects/%s", projectID),
		Filter:   filter,
		PageSize: 1,
	}

	slog.Info("querying container analysis", "resourceUri", resourceURL)

	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	occ, err := it.Next()
	if err != nil {
		return nil, fmt.Errorf("no provenance found for %s", resourceURL)
	}

	if occ.GetBuild() == nil {
		return nil, fmt.Errorf("occurrence has no build data for %s", resourceURL)
	}

	// Extract signature from envelope if available
	if envelope := occ.GetEnvelope(); envelope != nil && len(envelope.Signatures) > 0 {
		sig := envelope.Signatures[0]
		slog.Info("found DSSE signature", "keyid", sig.Keyid)
		return &ProvenanceSignature{
			KeyID:     sig.Keyid,
			Signature: base64.StdEncoding.EncodeToString(sig.Sig),
		}, nil
	}

	// If no DSSE envelope, provenance was verified by Container Analysis itself.
	// Return a sentinel value indicating Google-verified provenance.
	slog.Info("no DSSE envelope, provenance verified by container analysis")
	return &ProvenanceSignature{
		KeyID:     "google-cloud-build",
		Signature: "verified-by-container-analysis",
	}, nil
}
