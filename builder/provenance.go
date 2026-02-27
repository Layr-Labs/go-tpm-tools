package main

import (
	"archive/tar"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	grafeas "google.golang.org/genproto/googleapis/grafeas/v1"
)

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
	GitURL        string // Source repository URL from provenance
	SourceSHA     string // Source commit SHA from provenance
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
	}

	// Fetch provenance
	slog.Info("querying provenance", "resourceUri", provenanceRef)
	prov, err := fetchProvenance(ctx, config.ProjectID, provenanceRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch launcher provenance: %w", err)
	}
	result.Signature = prov.Signature
	result.GitURL = prov.GitURL
	result.SourceSHA = prov.SourceSHA
	slog.Info("launcher provenance fetched")

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

	// Query Container Analysis for provenance
	slog.Info("querying provenance", "resourceUri", provenanceRef)
	prov, err := fetchProvenance(ctx, config.ProjectID, provenanceRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch builder provenance: %w", err)
	}

	result.Signature = prov.Signature
	result.GitURL = prov.GitURL
	result.SourceSHA = prov.SourceSHA
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

// fetchProvenance queries Container Analysis for provenance on a container image.
// Returns the DSSE signature and source info for offline verification.
func fetchProvenance(ctx context.Context, projectID, resourceURL string) (*ProvenanceResult, error) {
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

	result := &ProvenanceResult{}

	// Extract and verify signature from envelope
	envelope := occ.GetEnvelope()
	if envelope == nil || len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("no DSSE envelope found for %s (expected Cloud Build provenance)", resourceURL)
	}

	sig := envelope.Signatures[0]
	slog.Info("found DSSE signature", "keyid", sig.Keyid)

	// Extract source info: try proto fields first, fall back to envelope payload.
	// The gRPC API doesn't always populate GetInTotoSlsaProvenanceV1() for v1 provenance,
	// but the envelope payload always contains the full in-toto statement.
	result.GitURL, result.SourceSHA, err = extractSourceInfo(occ.GetBuild())
	if err != nil {
		slog.Info("proto fields didn't contain source info, trying envelope payload")
		result.GitURL, result.SourceSHA, err = extractSourceInfoFromEnvelope(envelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to extract source info for %s: %w", resourceURL, err)
		}
	}

	if err := verifyDSSESignature(ctx, envelope); err != nil {
		return nil, fmt.Errorf("DSSE signature verification failed for %s: %w", resourceURL, err)
	}
	slog.Info("DSSE signature verified", "keyid", sig.Keyid)

	result.Signature = &ProvenanceSignature{
		KeyID:     sig.Keyid,
		Signature: base64.StdEncoding.EncodeToString(sig.Sig),
	}
	return result, nil
}

// extractSourceInfo extracts the git URL and commit SHA from a build occurrence.
// Tries SLSA v1 (ResolvedDependencies) first, then falls back to SLSA v0.2 (Materials).
func extractSourceInfo(build *grafeas.BuildOccurrence) (string, string, error) {
	// Try SLSA v1: ResolvedDependencies
	if v1 := build.GetInTotoSlsaProvenanceV1(); v1 != nil {
		for _, dep := range v1.GetPredicate().GetBuildDefinition().GetResolvedDependencies() {
			if uri := dep.GetUri(); uri != "" {
				for _, key := range []string{"gitCommit", "sha1"} {
					if sha, ok := dep.GetDigest()[key]; ok {
						return uri, sha, nil
					}
				}
			}
		}
	}

	// Try SLSA v0.2: Materials
	if stmt := build.GetIntotoStatement(); stmt != nil {
		for _, m := range stmt.GetSlsaProvenanceZeroTwo().GetMaterials() {
			if uri := m.GetUri(); uri != "" {
				if sha, ok := m.GetDigest()["sha1"]; ok {
					return uri, sha, nil
				}
			}
		}
	}

	// Try SLSA v0.1: IntotoStatement → SlsaProvenance → Materials
	if stmt := build.GetIntotoStatement(); stmt != nil {
		for _, m := range stmt.GetSlsaProvenance().GetMaterials() {
			if uri := m.GetUri(); uri != "" {
				if sha, ok := m.GetDigest()["sha1"]; ok {
					return uri, sha, nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("no source info found in provenance")
}

// extractSourceInfoFromEnvelope parses the DSSE envelope payload (JSON in-toto statement)
// to extract git URL and commit SHA. This handles cases where the gRPC API doesn't
// populate the proto fields but the envelope payload contains the full provenance.
func extractSourceInfoFromEnvelope(payload []byte) (string, string, error) {
	var stmt struct {
		Predicate struct {
			// SLSA v1: buildDefinition.resolvedDependencies
			BuildDefinition struct {
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			// SLSA v0.1/v0.2: materials
			Materials []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"materials"`
		} `json:"predicate"`
		SlsaProvenance struct {
			Materials []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"materials"`
		} `json:"slsaProvenance"`
	}

	if err := json.Unmarshal(payload, &stmt); err != nil {
		return "", "", fmt.Errorf("failed to parse envelope payload: %w", err)
	}

	digestKeys := []string{"gitCommit", "sha1"}

	// Try v1 resolvedDependencies
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if dep.URI != "" {
			for _, key := range digestKeys {
				if sha, ok := dep.Digest[key]; ok {
					return dep.URI, sha, nil
				}
			}
		}
	}

	// Try v0.2 predicate.materials
	for _, m := range stmt.Predicate.Materials {
		if m.URI != "" {
			for _, key := range digestKeys {
				if sha, ok := m.Digest[key]; ok {
					return m.URI, sha, nil
				}
			}
		}
	}

	// Try v0.1 slsaProvenance.materials
	for _, m := range stmt.SlsaProvenance.Materials {
		if m.URI != "" {
			for _, key := range digestKeys {
				if sha, ok := m.Digest[key]; ok {
					return m.URI, sha, nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("no source info found in envelope payload")
}

// verifyDSSESignature verifies a grafeas DSSE envelope by fetching the signing
// key from Cloud KMS and using the go-securesystemslib DSSE verifier.
func verifyDSSESignature(ctx context.Context, grafeasEnv *grafeas.Envelope) error {
	if len(grafeasEnv.Signatures) == 0 {
		return fmt.Errorf("envelope has no signatures")
	}

	// Strip gcpkms:// prefix to get the KMS resource name
	keyID := grafeasEnv.Signatures[0].Keyid
	kmsResourceName := strings.TrimPrefix(keyID, "gcpkms://")

	// Fetch the public key from Cloud KMS
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}
	defer kmsClient.Close()

	pubKeyResp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: kmsResourceName,
	})
	if err != nil {
		return fmt.Errorf("failed to get public key from KMS (%s): %w", kmsResourceName, err)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from KMS public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("KMS key is not ECDSA (got %T)", pubKey)
	}

	return verifyGrafeasEnvelope(ctx, grafeasEnv, ecdsaKey, keyID)
}

// verifyGrafeasEnvelope converts a grafeas DSSE envelope (raw bytes) to a
// go-securesystemslib dsse.Envelope (base64 strings) and verifies the signature.
func verifyGrafeasEnvelope(ctx context.Context, grafeasEnv *grafeas.Envelope, pubKey *ecdsa.PublicKey, keyID string) error {
	if len(grafeasEnv.Signatures) == 0 {
		return fmt.Errorf("envelope has no signatures")
	}

	// Convert grafeas envelope to go-securesystemslib dsse.Envelope
	dsseEnv := &dsse.Envelope{
		PayloadType: grafeasEnv.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(grafeasEnv.Payload),
	}
	for _, gs := range grafeasEnv.Signatures {
		dsseEnv.Signatures = append(dsseEnv.Signatures, dsse.Signature{
			KeyID: gs.Keyid,
			Sig:   base64.StdEncoding.EncodeToString(gs.Sig),
		})
	}

	// Create a DSSE verifier and verify the envelope
	v := &ecdsaVerifier{key: pubKey, keyID: keyID}
	envelopeVerifier, err := dsse.NewEnvelopeVerifier(v)
	if err != nil {
		return fmt.Errorf("failed to create envelope verifier: %w", err)
	}

	_, err = envelopeVerifier.Verify(ctx, dsseEnv)
	if err != nil {
		return fmt.Errorf("envelope verification failed: %w", err)
	}

	return nil
}

// ecdsaVerifier implements the dsse.Verifier interface for ECDSA public keys.
type ecdsaVerifier struct {
	key   *ecdsa.PublicKey
	keyID string
}

func (v *ecdsaVerifier) Verify(ctx context.Context, data, sig []byte) error {
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(v.key, hash[:], sig) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

func (v *ecdsaVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

func (v *ecdsaVerifier) Public() crypto.PublicKey {
	return v.key
}
