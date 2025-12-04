// Package main implements a simple workload that requests attestation and sends it to a KMS.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	teeServerSocket = "/run/container_launcher/teeserver.sock"
	retryInterval   = 10 * time.Second
	maxRetries      = 30
)

// NonceResponse from KMS /v1/nonce
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// AttestResponse from KMS /v1/attest
type AttestResponse struct {
	Success bool   `json:"success"`
	Secret  string `json:"secret,omitempty"`
	Error   string `json:"error,omitempty"`
}

func main() {
	kmsURL := os.Getenv("KMS_URL")
	if kmsURL == "" {
		log("ERROR: KMS_URL environment variable required")
		os.Exit(1)
	}

	log("=== TDX Attestation Workload ===")
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

		// Step 1: Get nonce from KMS
		log("Step 1: Getting nonce from KMS...")
		nonce, err := getNonce(kmsClient, kmsURL)
		if err != nil {
			log("ERROR getting nonce: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}
		log("Got nonce: %s", nonce)

		// Step 2: Request attestation from TEE server with nonce
		log("Step 2: Requesting attestation from TEE server...")
		nonceBytes, _ := hex.DecodeString(nonce)
		attestation, err := getAttestation(teeClient, nonceBytes)
		if err != nil {
			log("ERROR getting attestation: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}
		log("Got attestation (quote size: %d bytes)", len(attestation))

		// Step 3: Send attestation to KMS
		log("Step 3: Sending attestation to KMS...")
		resp, err := sendAttestation(kmsClient, kmsURL, attestation)
		if err != nil {
			log("ERROR sending attestation: %v", err)
			log("Retrying in %v...", retryInterval)
			time.Sleep(retryInterval)
			continue
		}

		if resp.Success {
			log("\n=== SUCCESS ===")
			log("Received secret: %s", resp.Secret)
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

func waitForSocket(path string) error {
	for range 60 {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("socket %s not available after 60 seconds", path)
}

func getNonce(client *http.Client, kmsURL string) (string, error) {
	resp, err := client.Get(kmsURL + "/v1/nonce")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("KMS returned status %d: %s", resp.StatusCode, string(body))
	}

	var nonceResp NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return "", err
	}
	return nonceResp.Nonce, nil
}

func getAttestation(client *http.Client, nonce []byte) ([]byte, error) {
	// The TEE server expects nonce in JSON body for POST requests
	reqBody, _ := json.Marshal(map[string][]byte{"nonce": nonce})
	resp, err := client.Post("http://localhost/v1/raw-attestation", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TEE server returned status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func sendAttestation(client *http.Client, kmsURL string, attestation []byte) (*AttestResponse, error) {
	resp, err := client.Post(kmsURL+"/v1/attest", "application/json", bytes.NewReader(attestation))
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
