// Package main implements a simple workload that requests attestation and sends it to a KMS.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	pb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

const (
	teeServerSocket = "/run/container_launcher/teeserver.sock"
	retryInterval   = 10 * time.Second
	maxRetries      = 30
)

// Platform represents the CVM technology type.
type Platform string

const (
	PlatformTDX     Platform = "tdx"
	PlatformSevSnp  Platform = "sevsnp"
	PlatformUnknown Platform = "unknown"
)

// AttestRequest is the request format for the KMS /v1/attest endpoint.
// Works with both TDX and SEV-SNP platforms.
type AttestRequest struct {
	// Attestation is a serialized pb.Attestation from ak.Attest()
	// Contains: TPM quotes, event log, AK certs, CEL, TDX/SEV-SNP quote
	Attestation []byte `json:"attestation"`

	// RSAPublicKey is the PEM-encoded ephemeral RSA public key for response encryption
	RSAPublicKey string `json:"rsa_public_key"`
}

// AttestResponse from KMS /v1/attest endpoint
type AttestResponse struct {
	Success         bool   `json:"success"`
	EncryptedSecret []byte `json:"encrypted_secret,omitempty"` // RSA-OAEP encrypted
	Error           string `json:"error,omitempty"`
}

// attestationResponse matches the teeserver /v1/attestation response format.
type attestationResponse struct {
	Attestation []byte `json:"attestation"` // Serialized pb.Attestation
}

func main() {
	kmsURL := os.Getenv("KMS_URL")
	if kmsURL == "" {
		log("ERROR: KMS_URL environment variable required")
		os.Exit(1)
	}

	log("=== CVM Attestation Workload ===")
	log("KMS URL: %s", kmsURL)

	// Wait for TEE server socket
	log("Waiting for TEE server socket...")
	if err := waitForSocket(teeServerSocket); err != nil {
		log("ERROR: %v", err)
		os.Exit(1)
	}
	log("TEE server socket available")

	// Create HTTP client for unix socket
	teeClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", teeServerSocket)
			},
		},
	}

	// Create HTTP client for KMS
	kmsClient := &http.Client{Timeout: 30 * time.Second}

	// Retry loop - KMS might reject until base image is added to allowlist
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log("\n=== Attempt %d/%d ===", attempt, maxRetries)

		// Step 1: Generate ephemeral RSA key pair
		log("Step 1: Generating ephemeral RSA key pair...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log("ERROR generating RSA key: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}

		// Encode public key to PEM
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			log("ERROR marshaling public key: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyDER,
		})
		log("Generated RSA public key")

		// Step 2: Request attestation from TEE server
		// The nonce is SHA256(RSA public key PEM) which binds the attestation to our key
		log("Step 2: Requesting attestation from TEE server...")
		attestResp, err := getAttestation(teeClient, pubKeyPEM)
		if err != nil {
			log("ERROR getting attestation: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}

		// Parse attestation to detect platform
		var attestation pb.Attestation
		if err := proto.Unmarshal(attestResp.Attestation, &attestation); err != nil {
			log("ERROR parsing attestation: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}

		platform := detectPlatform(&attestation)
		log("Detected platform: %s", platform)
		log("Got attestation (%d bytes)", len(attestResp.Attestation))

		// Send attestation to KMS
		log("Step 3: Sending attestation to KMS...")
		req := AttestRequest{
			Attestation:  attestResp.Attestation,
			RSAPublicKey: string(pubKeyPEM),
		}
		resp, err := sendAttestation(kmsClient, kmsURL, &req)
		if err != nil {
			log("ERROR sending attestation: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}

		if resp.Success {
			// Decrypt the response with our ephemeral private key
			log("Step 4: Decrypting response with ephemeral private key...")
			secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, resp.EncryptedSecret, nil)
			if err != nil {
				log("ERROR decrypting secret: %v", err)
				log("Retrying in %v...", retryInterval)
				time.Sleep(retryInterval)
				continue
			}

			log("\n=== SUCCESS ===")
			log("Received secret: %s", string(secret))
			log("Attestation verified and secret released!")
			break
		} else {
			log("KMS rejected attestation: %s", resp.Error)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
		}
	}

	// Keep container running
	log("\nWorkload complete. Container will keep running for debugging.")
	select {}
}

// detectPlatform determines the platform from the attestation.
func detectPlatform(attestation *pb.Attestation) Platform {
	if attestation.GetTdxAttestation() != nil {
		return PlatformTDX
	}
	if attestation.GetSevSnpAttestation() != nil {
		return PlatformSevSnp
	}
	return PlatformUnknown
}

func waitForSocket(path string) error {
	for range 60 {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("socket %s not available after 60 seconds", path)
}

func getAttestation(client *http.Client, rsaPubKeyPEM []byte) (*attestationResponse, error) {
	// Nonce = SHA256(RSA public key PEM), binds attestation to our key
	// Launcher embeds this in ReportData[0:32], adds AK hash in [32:64]
	rsaPubKeyHash := sha256.Sum256(rsaPubKeyPEM)
	reqBody, _ := json.Marshal(map[string][]byte{"nonce": rsaPubKeyHash[:]})
	resp, err := client.Post("http://localhost/v1/attestation", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TEE server returned status %d: %s", resp.StatusCode, string(body))
	}

	var attestResp attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestResp); err != nil {
		return nil, err
	}
	return &attestResp, nil
}

func sendAttestation(client *http.Client, kmsURL string, req *AttestRequest) (*AttestResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send to KMS
	resp, err := client.Post(kmsURL+"/v1/attest", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var attestResp AttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestResp); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %v, body: %s", err, string(body))
	}
	return &attestResp, nil
}

func log(format string, args ...any) {
	fmt.Printf(time.Now().Format("15:04:05")+" "+format+"\n", args...)
}
