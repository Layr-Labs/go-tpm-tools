package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"cloud.google.com/go/storage"
	grafeas "google.golang.org/genproto/googleapis/grafeas/v1"
)

// BuilderResult contains the builder container hash and provenance.
type BuilderResult struct {
	SHA256     string
	Provenance json.RawMessage
}

// SLSAProvenance represents the SLSA v1.0 provenance format from Cloud Build.
// See: https://slsa.dev/spec/v1.0/provenance
type SLSAProvenance struct {
	Type          string         `json:"_type"`
	Subject       []Subject      `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     ProvenancePred `json:"predicate"`
}

// Subject identifies the artifact the provenance is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ProvenancePred is the SLSA provenance predicate.
type ProvenancePred struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes what was built.
type BuildDefinition struct {
	BuildType            string          `json:"buildType"`
	ExternalParameters   json.RawMessage `json:"externalParameters"`
	InternalParameters   json.RawMessage `json:"internalParameters,omitempty"`
	ResolvedDependencies []Dependency    `json:"resolvedDependencies,omitempty"`
}

// Dependency represents a resolved dependency in the build.
type Dependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// RunDetails describes the build execution.
type RunDetails struct {
	Builder   Builder   `json:"builder"`
	Metadata  Metadata  `json:"metadata"`
	Byproduct Byproduct `json:"byproducts,omitempty"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// Metadata contains build metadata.
type Metadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// Byproduct contains additional build outputs.
type Byproduct struct {
	// Additional fields as needed
}

// fetchLauncherWithProvenance downloads the launcher binary and its SLSA provenance from a Docker image.
// Path format: docker://REGION/PROJECT/REPO/IMAGE/VERSION (e.g., docker://us-central1/my-project/launcher/launcher/v1.0.0)
// Returns the launcher hash, binary data, and provenance JSON (for embedding in manifest).
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
	hashHex := hex.EncodeToString(hash[:])
	log("Launcher size: %d bytes, SHA256: %s", len(launcherData), hashHex)

	result := &LauncherResult{
		SHA256: hashHex,
		Data:   launcherData,
	}

	// Fetch provenance using the image digest
	// Build resourceUri: https://REGION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:DIGEST
	imageBase := imageRef
	if idx := strings.LastIndex(imageRef, ":"); idx != -1 {
		imageBase = imageRef[:idx]
	}
	resourceURI := "https://" + imageBase + "@" + imageDigest
	log("Querying provenance with resourceUri: %s", resourceURI)

	provenanceData, err := fetchContainerProvenanceByDigest(ctx, config.ProjectID, resourceURI, imageDigest)
	if err != nil {
		log("WARNING: Could not fetch launcher provenance: %v", err)
	} else {
		result.Provenance = provenanceData
		log("Launcher provenance fetched (%d bytes)", len(provenanceData))
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
	log("Downloading launcher from Docker image: %s...", imageRef)

	// Get the image digest by pulling manifest
	digest, err := getImageDigest(ctx, imageRef)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get image digest: %w", err)
	}
	log("  Image digest: %s", digest)

	// Extract the launcher binary from the image
	// The image is FROM scratch with just /launcher, so we extract that file
	data, err := extractFileFromImage(ctx, imageRef, "/launcher")
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to extract launcher from image: %w", err)
	}

	return data, digest, imageRef, nil
}

// getImageDigest gets the digest of a container image.
func getImageDigest(ctx context.Context, imageRef string) (string, error) {
	// Use the Artifact Registry API to get the image manifest/digest
	// Parse the image reference to extract components
	// Format: REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG

	// Get access token
	tokenSource, err := findDefaultCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get credentials: %w", err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	// Parse the image reference
	// us-central1-docker.pkg.dev/project/repo/image:tag
	parts := strings.SplitN(imageRef, "/", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid image reference: %s", imageRef)
	}
	registry := parts[0]
	project := parts[1]
	repo := parts[2]
	imageAndTag := parts[3]

	imageName := imageAndTag
	tag := "latest"
	if idx := strings.LastIndex(imageAndTag, ":"); idx != -1 {
		imageName = imageAndTag[:idx]
		tag = imageAndTag[idx+1:]
	}

	// Call the Docker Registry v2 API to get the manifest
	manifestURL := fmt.Sprintf("https://%s/v2/%s/%s/%s/manifests/%s", registry, project, repo, imageName, tag)
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get manifest: %d: %s", resp.StatusCode, string(body))
	}

	// The digest is in the Docker-Content-Digest header
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no digest in response headers")
	}

	return digest, nil
}

// extractFileFromImage extracts a file from a container image.
func extractFileFromImage(ctx context.Context, imageRef, filePath string) ([]byte, error) {
	// Get access token
	tokenSource, err := findDefaultCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Parse the image reference
	parts := strings.SplitN(imageRef, "/", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid image reference: %s", imageRef)
	}
	registry := parts[0]
	project := parts[1]
	repo := parts[2]
	imageAndTag := parts[3]

	imageName := imageAndTag
	tag := "latest"
	if idx := strings.LastIndex(imageAndTag, ":"); idx != -1 {
		imageName = imageAndTag[:idx]
		tag = imageAndTag[idx+1:]
	}

	// Get the manifest to find the layer
	manifestURL := fmt.Sprintf("https://%s/v2/%s/%s/%s/manifests/%s", registry, project, repo, imageName, tag)
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get manifest: %d: %s", resp.StatusCode, string(body))
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers in manifest")
	}

	// For a FROM scratch image with one file, there's typically one layer
	// Download the layer (it's a tar.gz containing the file)
	layerDigest := manifest.Layers[0].Digest
	log("  Downloading layer: %s", layerDigest)

	blobURL := fmt.Sprintf("https://%s/v2/%s/%s/%s/blobs/%s", registry, project, repo, imageName, layerDigest)
	req, err = http.NewRequestWithContext(ctx, "GET", blobURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get layer: %d: %s", resp.StatusCode, string(body))
	}

	// The layer is a gzipped tar archive
	return extractFileFromTarGz(resp.Body, filePath)
}

// extractFileFromTarGz extracts a single file from a gzipped tar archive.
func extractFileFromTarGz(r io.Reader, targetPath string) ([]byte, error) {
	// Strip leading slash for tar path comparison
	targetPath = strings.TrimPrefix(targetPath, "/")

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
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

// tokenSourceWrapper wraps oauth2.TokenSource to match our interface
type tokenSourceWrapper struct {
	token string
}

func (t *tokenSourceWrapper) Token() (*struct {
	AccessToken string
	TokenType   string
}, error) {
	return &struct {
		AccessToken string
		TokenType   string
	}{AccessToken: t.token, TokenType: "Bearer"}, nil
}

// findDefaultCredentials gets the default Google credentials
func findDefaultCredentials(ctx context.Context) (*tokenSourceWrapper, error) {
	// In a GCE environment, use the metadata service
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenSourceWrapper{token: tokenResp.AccessToken}, nil
}

// uploadToGCS uploads data to a GCS object.
func uploadToGCS(ctx context.Context, bucket, object string, data []byte) error {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	writer := client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return nil
}

// fetchBuilderProvenance gets the builder container's digest and SLSA provenance.
// The digest is obtained from a GCA token, and provenance is fetched from Container Analysis API.
func fetchBuilderProvenance(ctx context.Context, config *Config) (*BuilderResult, error) {
	// Request a GCA token with a dummy nonce to get the container info
	log("Requesting GCA token to get container digest...")
	token, err := requestGCAAttestation(ctx, config, []byte("digest-lookup"))
	if err != nil {
		return nil, fmt.Errorf("failed to get GCA token for digest lookup: %w", err)
	}

	// Parse the JWT to extract container info from submods.container
	digest, imageRef, err := parseContainerInfoFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container info from token: %w", err)
	}

	// Strip sha256: prefix for consistent format with launcher
	sha256Hash := strings.TrimPrefix(digest, "sha256:")

	log("Builder container: %s", imageRef)
	log("Builder SHA256: %s", sha256Hash)

	result := &BuilderResult{
		SHA256: sha256Hash,
	}

	// Query Container Analysis for provenance
	// The resourceUri format in Container Analysis uses digest, not tag:
	// https://REGION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:DIGEST
	// Extract the image base (without tag) and append digest
	imageBase := imageRef
	if idx := strings.LastIndex(imageRef, ":"); idx != -1 {
		// Remove the tag (e.g., :v0.7.0) but keep the image path
		imageBase = imageRef[:idx]
	}
	resourceURL := "https://" + imageBase + "@" + digest
	log("Querying provenance with resourceUri: %s", resourceURL)

	provenanceData, err := fetchContainerProvenanceByDigest(ctx, config.ProjectID, resourceURL, digest)
	if err != nil {
		// Store the error details in the result so we can debug
		log("WARNING: Could not fetch builder provenance: %v", err)
		log("  Query URL was: %s", resourceURL)
		log("  Query digest was: %s", digest)
		return result, nil
	}

	result.Provenance = provenanceData
	return result, nil
}

// parseContainerInfoFromToken extracts container digest and image reference from a GCA JWT.
func parseContainerInfoFromToken(token string) (digest, imageRef string, err error) {
	// JWT is header.payload.signature - we need the payload
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (base64url encoded)
	payload, err := base64URLDecode(parts[1])
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

// base64URLDecode decodes a base64url-encoded string (JWT uses base64url without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// fetchContainerProvenanceByDigest queries Container Analysis for provenance on a container image.
func fetchContainerProvenanceByDigest(ctx context.Context, projectID, resourceURL, digest string) (json.RawMessage, error) {
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Container Analysis client: %w", err)
	}
	defer client.Close()

	grafeasClient := client.GetGrafeasClient()

	// Query for BUILD occurrences - use simple filter, match resourceUri in code
	// The resourceUri filter may not work correctly with the Go API
	filter := `kind="BUILD"`
	parent := fmt.Sprintf("projects/%s", projectID)

	log("Querying Container Analysis for builder provenance...")
	log("  Looking for resourceUri: %s", resourceURL)

	req := &grafeas.ListOccurrencesRequest{
		Parent: parent,
		Filter: filter,
	}

	it := grafeasClient.ListOccurrences(ctx, req)
	occCount := 0
	matchingUriCount := 0
	for {
		occ, err := it.Next()
		if err != nil {
			log("  Iterator done after %d total occurrences (%d matching URI)", occCount, matchingUriCount)
			break
		}
		occCount++

		// Filter by resourceUri in code since the API filter may not work
		occUri := occ.GetResourceUri()
		if occUri != resourceURL {
			continue
		}
		matchingUriCount++
		log("  Found occurrence with matching resourceUri")

		if occ.GetBuild() == nil {
			log("    No build data")
			continue
		}

		// Try SLSA v1 format first
		if prov := occ.GetBuild().GetInTotoSlsaProvenanceV1(); prov != nil {
			log("    Found SLSA v1 provenance with %d subjects", len(prov.Subject))
			for _, subject := range prov.Subject {
				if sha256Hash, ok := subject.Digest["sha256"]; ok {
					expectedHash := strings.TrimPrefix(digest, "sha256:")
					log("    Subject hash: %s, expected: %s", sha256Hash, expectedHash)
					if sha256Hash == expectedHash {
						provenanceJSON, err := json.Marshal(prov)
						if err != nil {
							return nil, fmt.Errorf("failed to serialize provenance: %w", err)
						}
						log("  Found matching provenance!")
						return provenanceJSON, nil
					}
				}
			}
		}

		// Try older intoto statement format (v0.1)
		if stmt := occ.GetBuild().GetIntotoStatement(); stmt != nil {
			log("    Found intoto statement with %d subjects", len(stmt.Subject))
			for _, subject := range stmt.Subject {
				if sha256Hash, ok := subject.Digest["sha256"]; ok {
					expectedHash := strings.TrimPrefix(digest, "sha256:")
					if sha256Hash == expectedHash {
						provenanceJSON, err := json.Marshal(stmt)
						if err != nil {
							return nil, fmt.Errorf("failed to serialize provenance: %w", err)
						}
						log("  Found matching provenance (v0.1 format)!")
						return provenanceJSON, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no provenance found for container %s (checked %d occurrences, %d matching URI)", resourceURL, occCount, matchingUriCount)
}
