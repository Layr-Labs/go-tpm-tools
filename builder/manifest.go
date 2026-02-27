package main

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Manifest represents a build manifest binding provenance to output.
type Manifest struct {
	Version       string            `json:"version"`
	Timestamp     time.Time         `json:"timestamp"`
	Source        SourceInfo        `json:"source"`
	BuilderImages map[string]string `json:"builder_images"`
	BaseImage     ImageRef          `json:"base_image"`
	Output        ImageRef          `json:"output"`
	CloudBuildID  string            `json:"cloud_build_id"`
}

// SourceInfo contains provenance information for build inputs.
type SourceInfo struct {
	Launcher ArtifactInfo `json:"launcher"`
	Builder  ArtifactInfo `json:"builder"`
}

// ArtifactInfo contains hash and provenance details for an artifact.
type ArtifactInfo struct {
	BinaryDigest  string               `json:"binary_digest,omitempty"`
	ImageDigest   string               `json:"image_digest,omitempty"`
	ProvenanceRef string               `json:"provenance_ref"`
	GitURL        string               `json:"git_url,omitempty"`
	SourceSHA     string               `json:"source_sha,omitempty"`
	Signature     *ProvenanceSignature `json:"signature,omitempty"`
}

// ProvenanceSignature contains a SLSA provenance signature.
type ProvenanceSignature struct {
	KeyID     string `json:"keyid,omitempty"`
	Signature string `json:"sig"`
}

// ProvenanceResult contains the signature and source info extracted from provenance.
type ProvenanceResult struct {
	Signature *ProvenanceSignature
	GitURL    string // Source repository URL
	SourceSHA string // Source commit SHA
}

// ImageRef identifies a GCE image.
type ImageRef struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Project string `json:"project"`
}

// BuildAttestation contains the complete attestation for a build.
type BuildAttestation struct {
	Manifest       Manifest `json:"manifest"`
	ManifestDigest string   `json:"manifest_digest"`
	GCAToken       string   `json:"gca_token"`
}

// LauncherResult contains the fetched launcher artifact and its provenance.
type LauncherResult struct {
	BinaryDigest  string // SHA256 hash of the launcher binary
	ImageDigest   string // Container image digest
	ProvenanceRef string
	GitURL        string // Source repository URL from provenance
	SourceSHA     string // Source commit SHA from provenance
	Signature     *ProvenanceSignature
}

func newManifest(config *Config, launcher *LauncherResult, builder *BuilderResult, build *BuildResult) Manifest {
	return Manifest{
		Version:   "1",
		Timestamp: time.Now().UTC(),
		Source: SourceInfo{
			Launcher: ArtifactInfo{
				BinaryDigest:  launcher.BinaryDigest,
				ImageDigest:   launcher.ImageDigest,
				ProvenanceRef: launcher.ProvenanceRef,
				GitURL:        launcher.GitURL,
				SourceSHA:     launcher.SourceSHA,
				Signature:     launcher.Signature,
			},
			Builder: ArtifactInfo{
				ImageDigest:   builder.ImageDigest,
				ProvenanceRef: builder.ProvenanceRef,
				GitURL:        builder.GitURL,
				SourceSHA:     builder.SourceSHA,
				Signature:     builder.Signature,
			},
		},
		BuilderImages: build.BuilderImages,
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
