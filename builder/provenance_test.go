package main

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestStripImageTag(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
		want     string
	}{
		{
			name:     "with tag",
			imageRef: "us-central1-docker.pkg.dev/project/repo/image:v1.0.0",
			want:     "us-central1-docker.pkg.dev/project/repo/image",
		},
		{
			name:     "without tag",
			imageRef: "us-central1-docker.pkg.dev/project/repo/image",
			want:     "us-central1-docker.pkg.dev/project/repo/image",
		},
		{
			name:     "registry with port and tag",
			imageRef: "registry:5000/project/image:latest",
			want:     "registry:5000/project/image",
		},
		{
			name:     "empty string",
			imageRef: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripImageTag(tt.imageRef)
			if got != tt.want {
				t.Errorf("stripImageTag(%q) = %q, want %q", tt.imageRef, got, tt.want)
			}
		})
	}
}

func TestExtractFileFromTar(t *testing.T) {
	// Helper to create a tar archive in memory with the given files.
	makeTar := func(t *testing.T, files map[string][]byte) *bytes.Reader {
		t.Helper()
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for name, content := range files {
			if err := tw.WriteHeader(&tar.Header{
				Name: name,
				Size: int64(len(content)),
				Mode: 0644,
			}); err != nil {
				t.Fatalf("failed to write tar header for %s: %v", name, err)
			}
			if _, err := tw.Write(content); err != nil {
				t.Fatalf("failed to write tar content for %s: %v", name, err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("failed to close tar writer: %v", err)
		}
		return bytes.NewReader(buf.Bytes())
	}

	t.Run("file found", func(t *testing.T) {
		r := makeTar(t, map[string][]byte{"launcher": []byte("binary-data")})
		data, err := extractFileFromTar(r, "/launcher")
		if err != nil {
			t.Fatalf("extractFileFromTar() error: %v", err)
		}
		if string(data) != "binary-data" {
			t.Errorf("extractFileFromTar() = %q, want %q", data, "binary-data")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		r := makeTar(t, map[string][]byte{"other-file": []byte("data")})
		_, err := extractFileFromTar(r, "/launcher")
		if err == nil {
			t.Error("extractFileFromTar() should return error for missing file")
		}
	})

	t.Run("empty archive", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		tw.Close()
		_, err := extractFileFromTar(bytes.NewReader(buf.Bytes()), "/launcher")
		if err == nil {
			t.Error("extractFileFromTar() should return error for empty archive")
		}
	})

	t.Run("dot-slash prefix normalization", func(t *testing.T) {
		r := makeTar(t, map[string][]byte{"./launcher": []byte("normalized")})
		data, err := extractFileFromTar(r, "/launcher")
		if err != nil {
			t.Fatalf("extractFileFromTar() error: %v", err)
		}
		if string(data) != "normalized" {
			t.Errorf("extractFileFromTar() = %q, want %q", data, "normalized")
		}
	})

	t.Run("multiple files picks correct one", func(t *testing.T) {
		r := makeTar(t, map[string][]byte{
			"bin/other":  []byte("wrong"),
			"launcher":   []byte("correct"),
			"bin/helper": []byte("also-wrong"),
		})
		data, err := extractFileFromTar(r, "/launcher")
		if err != nil {
			t.Fatalf("extractFileFromTar() error: %v", err)
		}
		if string(data) != "correct" {
			t.Errorf("extractFileFromTar() = %q, want %q", data, "correct")
		}
	})
}

func TestDownloadLauncherFromDockerImage_InvalidPaths(t *testing.T) {
	tests := []struct {
		name       string
		dockerPath string
	}{
		{
			name:       "too few parts",
			dockerPath: "docker://us-central1/project/repo/image",
		},
		{
			name:       "too many parts",
			dockerPath: "docker://us-central1/project/repo/image/version/extra",
		},
		{
			name:       "empty path after prefix",
			dockerPath: "docker://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := downloadLauncherFromDockerImage(t.Context(), tt.dockerPath)
			if err == nil {
				t.Error("downloadLauncherFromDockerImage() should return error for invalid path")
			}
		})
	}
}

func TestParseContainerInfoFromToken(t *testing.T) {
	// Create a minimal JWT with container info in the payload
	// JWT format: header.payload.signature
	// We only care about the payload for this test

	tests := []struct {
		name        string
		token       string
		wantDigest  string
		wantRef     string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid token with container info",
			// Payload: {"submods":{"container":{"image_digest":"sha256:abc123","image_reference":"us-central1-docker.pkg.dev/project/repo/image:tag"}}}
			token:      "eyJhbGciOiJSUzI1NiJ9.eyJzdWJtb2RzIjp7ImNvbnRhaW5lciI6eyJpbWFnZV9kaWdlc3QiOiJzaGEyNTY6YWJjMTIzIiwiaW1hZ2VfcmVmZXJlbmNlIjoidXMtY2VudHJhbDEtZG9ja2VyLnBrZy5kZXYvcHJvamVjdC9yZXBvL2ltYWdlOnRhZyJ9fX0.signature",
			wantDigest: "sha256:abc123",
			wantRef:    "us-central1-docker.pkg.dev/project/repo/image:tag",
			wantErr:    false,
		},
		{
			name:        "invalid JWT format - too few parts",
			token:       "header.payload",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "invalid JWT format - too many parts",
			token:       "header.payload.signature.extra",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "invalid base64 payload",
			token:       "header.!!!invalid!!!.signature",
			wantErr:     true,
			errContains: "decode",
		},
		{
			name: "missing container digest",
			// Payload: {"submods":{"container":{"image_reference":"ref"}}}
			token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWJtb2RzIjp7ImNvbnRhaW5lciI6eyJpbWFnZV9yZWZlcmVuY2UiOiJyZWYifX19.signature",
			wantErr:     true,
			errContains: "no container digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, ref, err := parseContainerInfoFromToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseContainerInfoFromToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseContainerInfoFromToken() error = %v, should contain %q", err, tt.errContains)
				}
				return
			}
			if digest != tt.wantDigest {
				t.Errorf("parseContainerInfoFromToken() digest = %q, want %q", digest, tt.wantDigest)
			}
			if ref != tt.wantRef {
				t.Errorf("parseContainerInfoFromToken() ref = %q, want %q", ref, tt.wantRef)
			}
		})
	}
}
