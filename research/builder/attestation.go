package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	log("Waiting for TEE server socket...")
	if err := waitForTeeSocket(); err != nil {
		return "", fmt.Errorf("TEE server socket not available: %w", err)
	}
	log("TEE server socket available")

	// Request token with custom nonce
	return requestTokenFromLauncher(ctx, nonce, config.GCAEndpoint)
}

// waitForTeeSocket waits for the teeserver socket to become available.
func waitForTeeSocket() error {
	for i := 0; i < 60; i++ {
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

	log("Requesting attestation token with nonce: %s...", nonceB64[:16])

	// POST to the teeserver /v1/token endpoint
	resp, err := httpClient.Post("http://localhost/v1/token", "application/json", bytes.NewReader(reqBody))
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

// storeAttestation stores the build attestation to GCS.
func storeAttestation(ctx context.Context, config *Config, attestation *BuildAttestation) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	// Create the attestation JSON
	attestationJSON, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal attestation: %w", err)
	}

	// Store path: gs://{bucket}/build-attestations/{image-name}/attestation.json
	objectPath := fmt.Sprintf("build-attestations/%s/attestation.json", config.OutputImageName)

	// Upload to GCS
	bucket := client.Bucket(config.AttestationBucket)
	obj := bucket.Object(objectPath)

	writer := obj.NewWriter(ctx)
	writer.ContentType = "application/json"

	if _, err := io.Copy(writer, bytes.NewReader(attestationJSON)); err != nil {
		writer.Close()
		return "", fmt.Errorf("failed to write attestation: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	fullPath := fmt.Sprintf("gs://%s/%s", config.AttestationBucket, objectPath)
	log("Stored attestation JSON at %s", fullPath)

	// Also store the GCA token separately for easy verification
	if attestation.GCAToken != "" {
		tokenPath := fmt.Sprintf("build-attestations/%s/gca_token.jwt", config.OutputImageName)
		tokenObj := bucket.Object(tokenPath)
		tokenWriter := tokenObj.NewWriter(ctx)
		tokenWriter.ContentType = "application/jwt"

		if _, err := tokenWriter.Write([]byte(attestation.GCAToken)); err != nil {
			tokenWriter.Close()
			return fullPath, fmt.Errorf("failed to write token: %w", err)
		}
		if err := tokenWriter.Close(); err != nil {
			return fullPath, fmt.Errorf("failed to close token writer: %w", err)
		}
		log("Stored GCA token at gs://%s/%s", config.AttestationBucket, tokenPath)
	}

	// Store the manifest separately for easy access
	manifestJSON, _ := json.MarshalIndent(attestation.Manifest, "", "  ")
	manifestPath := fmt.Sprintf("build-attestations/%s/manifest.json", config.OutputImageName)
	manifestObj := bucket.Object(manifestPath)
	manifestWriter := manifestObj.NewWriter(ctx)
	manifestWriter.ContentType = "application/json"

	if _, err := io.Copy(manifestWriter, bytes.NewReader(manifestJSON)); err != nil {
		manifestWriter.Close()
		return fullPath, fmt.Errorf("failed to write manifest: %w", err)
	}
	if err := manifestWriter.Close(); err != nil {
		return fullPath, fmt.Errorf("failed to close manifest writer: %w", err)
	}
	log("Stored manifest at gs://%s/%s", config.AttestationBucket, manifestPath)

	return fullPath, nil
}
