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
	SHA256        string               `json:"sha256"`
	ImageDigest   string               `json:"image_digest,omitempty"`
	ProvenanceRef string               `json:"provenance_ref"`
	Signature     *ProvenanceSignature `json:"signature,omitempty"`
}

// ProvenanceSignature contains a SLSA provenance signature.
type ProvenanceSignature struct {
	KeyID     string `json:"keyid,omitempty"`
	Signature string `json:"sig"`
}

// ImageRef identifies a GCE image.
type ImageRef struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Project string `json:"project"`
}

// BuildAttestation contains the complete attestation for a build.
type BuildAttestation struct {
	Manifest     Manifest `json:"manifest"`
	ManifestHash string   `json:"manifest_hash"`
	GCAToken     string   `json:"gca_token"`
}

// LauncherResult contains the fetched launcher artifact and its provenance.
type LauncherResult struct {
	SHA256        string
	ImageDigest   string
	ProvenanceRef string
	Signature     *ProvenanceSignature
	Data          []byte
}

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
