package main

import (
	"strings"
	"testing"
)

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "standard base64url without padding",
			input:   "SGVsbG8gV29ybGQ",
			want:    "Hello World",
			wantErr: false,
		},
		{
			name:    "base64url with URL-safe chars",
			input:   "PDw_Pz4-",
			want:    "<<??>>",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: false,
		},
		{
			name:    "base64url needing 2 padding chars",
			input:   "YQ",
			want:    "a",
			wantErr: false,
		},
		{
			name:    "base64url needing 1 padding char",
			input:   "YWI",
			want:    "ab",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64URLDecode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64URLDecode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("base64URLDecode() = %q, want %q", string(got), tt.want)
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
