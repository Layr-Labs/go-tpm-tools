package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/storage"
)

const (
	// teeServerSocket is the path to the launcher's teeserver socket
	teeServerSocket = "/run/container_launcher/teeserver.sock"
)

// TokenRequest is the request format for the teeserver /v1/token endpoint.
type TokenRequest struct {
	// Audience for the token
	Audience string `json:"audience"`

	// Nonces are custom values to embed in the token's eat_nonce claim
	// Up to 6 nonces, each base64-encoded
	Nonces []string `json:"nonces"`

	// TokenType is typically "OIDC" or "PKI"
	TokenType string `json:"token_type"`
}

// requestGCAAttestation requests an attestation token from the Confidential Space launcher.
// The nonce (manifest hash) is embedded in the token's eat_nonce claim, binding it to our build inputs.
//
// This function uses the launcher's teeserver socket at /run/container_launcher/teeserver.sock
// to request an OIDC token with custom nonces.
func requestGCAAttestation(ctx context.Context, config *Config, nonce []byte) (string, error) {
	// Wait for the teeserver socket to be available
	slog.Info("waiting for TEE server socket")
	if err := waitForTeeSocket(); err != nil {
		return "", fmt.Errorf("TEE server socket not available: %w", err)
	}
	slog.Info("TEE server socket available")

	// Request token with custom nonce
	return requestTokenFromLauncher(ctx, nonce, config.GCAEndpoint)
}

// waitForTeeSocket waits for the teeserver socket to become available.
func waitForTeeSocket() error {
	for range 60 {
		if _, err := os.Stat(teeServerSocket); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("socket %s not available after 60 seconds", teeServerSocket)
}

// requestTokenFromLauncher requests a token from the Confidential Space launcher.
// The launcher handles the attestation flow internally and returns a signed JWT
// with the nonce embedded in the eat_nonce claim.
func requestTokenFromLauncher(ctx context.Context, nonce []byte, audience string) (string, error) {
	// Create HTTP client that connects via the teeserver unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", teeServerSocket)
			},
		},
		Timeout: 30 * time.Second,
	}

	// The nonce must be base64-encoded for the token request
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	// Build the token request
	tokenReq := TokenRequest{
		Audience:  audience,
		Nonces:    []string{nonceB64},
		TokenType: "OIDC",
	}

	reqBody, err := json.Marshal(tokenReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	slog.Info("requesting attestation token", "nonce_prefix", nonceB64[:16])

	// POST to the teeserver /v1/token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// The response is the raw JWT token
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	return string(tokenBytes), nil
}

// writeToGCS writes data to a GCS object with the specified content type.
func writeToGCS(ctx context.Context, bucket *storage.BucketHandle, path, contentType string, data []byte) error {
	writer := bucket.Object(path).NewWriter(ctx)
	writer.ContentType = contentType
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}

// storeAttestation stores the build attestation to GCS.
func storeAttestation(ctx context.Context, config *Config, attestation *BuildAttestation) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	bucket := client.Bucket(config.ProvenanceBucket)

	// Store attestation.json
	attestationJSON, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal attestation: %w", err)
	}
	attestationPath := fmt.Sprintf("%s/attestation.json", config.OutputImageName)
	if err := writeToGCS(ctx, bucket, attestationPath, "application/json", attestationJSON); err != nil {
		return "", fmt.Errorf("failed to write attestation: %w", err)
	}
	fullPath := fmt.Sprintf("gs://%s/%s", config.ProvenanceBucket, attestationPath)
	slog.Info("stored attestation JSON", "path", fullPath)

	// Store GCA token separately for easy verification
	if attestation.GCAToken != "" {
		tokenPath := fmt.Sprintf("%s/gca_token.jwt", config.OutputImageName)
		if err := writeToGCS(ctx, bucket, tokenPath, "application/jwt", []byte(attestation.GCAToken)); err != nil {
			return fullPath, fmt.Errorf("failed to write token: %w", err)
		}
		slog.Info("stored GCA token", "path", fmt.Sprintf("gs://%s/%s", config.ProvenanceBucket, tokenPath))
	}

	// Store manifest separately for easy access
	manifestJSON, err := json.MarshalIndent(attestation.Manifest, "", "  ")
	if err != nil {
		return fullPath, fmt.Errorf("failed to marshal manifest: %w", err)
	}
	manifestPath := fmt.Sprintf("%s/manifest.json", config.OutputImageName)
	if err := writeToGCS(ctx, bucket, manifestPath, "application/json", manifestJSON); err != nil {
		return fullPath, fmt.Errorf("failed to write manifest: %w", err)
	}
	slog.Info("stored manifest", "path", fmt.Sprintf("gs://%s/%s", config.ProvenanceBucket, manifestPath))

	return fullPath, nil
}
