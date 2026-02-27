package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

// BuilderResult contains the builder container digest and provenance.
type BuilderResult struct {
	ImageDigest   string // Container image digest
	ProvenanceRef string // URL to fetch provenance
	GitURL        string // Source repository URL from provenance
	SourceSHA     string // Source commit SHA from provenance
	Signature     *ProvenanceSignature
}

// provenanceForDigest fetches SLSA provenance for an image with a known digest.
func provenanceForDigest(ctx context.Context, projectID, imageRef, imageDigest string) (*BuilderResult, error) {
	provenanceRef := "https://" + stripImageTag(imageRef) + "@" + imageDigest
	slog.Info("querying provenance", "resourceUri", provenanceRef)

	prov, err := fetchProvenance(ctx, projectID, provenanceRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provenance: %w", err)
	}

	return &BuilderResult{
		ImageDigest:   imageDigest,
		ProvenanceRef: provenanceRef,
		GitURL:        prov.GitURL,
		SourceSHA:     prov.SourceSHA,
		Signature:     prov.Signature,
	}, nil
}

// fetchImageProvenance resolves an image tag to a digest and fetches its SLSA provenance.
// Works for any Artifact Registry image reference (e.g., "REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG").
func fetchImageProvenance(ctx context.Context, projectID, imageRef string) (*BuilderResult, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(google.Keychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image: %w", err)
	}

	d, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("failed to get image digest: %w", err)
	}

	return provenanceForDigest(ctx, projectID, imageRef, d.String())
}

// fetchBuilderProvenance gets the builder container's digest and SLSA provenance signature.
// The digest is obtained from a GCA token, and provenance signature is fetched from Container Analysis API.
func fetchBuilderProvenance(ctx context.Context, config *Config) (*BuilderResult, error) {
	slog.Info("requesting GCA token for container digest")
	token, err := requestGCAAttestation(ctx, config, []byte("digest-lookup"))
	if err != nil {
		return nil, fmt.Errorf("failed to get GCA token for digest lookup: %w", err)
	}

	imageDigest, imageRef, err := parseContainerInfoFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container info from token: %w", err)
	}
	slog.Info("builder container identified", "ref", imageRef, "imageDigest", imageDigest)

	return provenanceForDigest(ctx, config.ProjectID, imageRef, imageDigest)
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

	// Query for BUILD occurrences with specific resourceUri.
	// Cloud Build may create multiple occurrences per image (v0.1 and v1 formats).
	// Iterate to find one with a valid DSSE envelope.
	filter := fmt.Sprintf(`kind="BUILD" AND resourceUri="%s"`, resourceURL)
	req := &grafeas.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		Filter: filter,
	}

	slog.Info("querying container analysis", "resourceUri", resourceURL)

	var occ *grafeas.Occurrence
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		candidate, err := it.Next()
		if err != nil {
			break
		}
		if candidate.GetBuild() == nil {
			continue
		}
		env := candidate.GetEnvelope()
		if env != nil && len(env.Signatures) > 0 {
			occ = candidate
			break
		}
		// Keep first occurrence with build data as fallback
		if occ == nil {
			occ = candidate
		}
	}

	if occ == nil {
		return nil, fmt.Errorf("no provenance found for %s", resourceURL)
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
