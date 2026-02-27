// PCR capture workload runs inside a CVM booted from the output image.
// It fetches an attestation from the TEE server, extracts SHA-256 PCR values
// (4, 8, 9), detects the platform, and uploads the result as JSON to GCS.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	tpmpb "github.com/Layr-Labs/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"
)

type pcrResult struct {
	Platform string            `json:"platform"`
	PCRs     map[string]string `json:"pcrs"`
}

func main() {
	gcsOutput := os.Getenv("GCS_OUTPUT")
	if gcsOutput == "" {
		fatal("GCS_OUTPUT env var is required")
	}

	socket := "/run/container_launcher/teeserver.sock"

	fmt.Fprintf(os.Stderr, "waiting for TEE server socket at %s\n", socket)
	if err := waitForSocket(socket, 60*time.Second); err != nil {
		fatal("socket wait: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
		Timeout: 30 * time.Second,
	}

	attestBytes, err := fetchAttestation(client)
	if err != nil {
		fatal("fetch attestation: %v", err)
	}

	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestBytes, &attestation); err != nil {
		fatal("unmarshal attestation: %v", err)
	}

	platform := detectPlatform(&attestation)
	fmt.Fprintf(os.Stderr, "detected platform: %s\n", platform)

	pcrs, err := extractPCRs(&attestation, []uint32{4, 8, 9})
	if err != nil {
		fatal("extract PCRs: %v", err)
	}

	result := pcrResult{
		Platform: platform,
		PCRs: map[string]string{
			"4": hex.EncodeToString(pcrs[4]),
			"8": hex.EncodeToString(pcrs[8]),
			"9": hex.EncodeToString(pcrs[9]),
		},
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatal("marshal result: %v", err)
	}

	fmt.Fprintf(os.Stderr, "uploading PCR result to %s\n", gcsOutput)
	if err := uploadToGCS(context.Background(), gcsOutput, data); err != nil {
		fatal("upload to GCS: %v", err)
	}
	fmt.Fprintf(os.Stderr, "done\n")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("socket %s did not appear within %v", path, timeout)
}

func fetchAttestation(client *http.Client) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	reqBody, err := json.Marshal(struct {
		Challenge string `json:"challenge"`
	}{
		Challenge: base64.StdEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := client.Post("http://localhost/v1/bound_evidence", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("POST /v1/bound_evidence: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}
	return respBytes, nil
}

func detectPlatform(attestation *attestpb.Attestation) string {
	if attestation.GetTdxAttestation() != nil {
		return "intel_tdx"
	}
	if attestation.GetSevSnpAttestation() != nil {
		return "amd_sev_snp"
	}
	if len(attestation.GetQuotes()) > 0 && len(attestation.GetAkCert()) > 0 {
		return "gcp_shielded_vm"
	}
	return "unknown"
}

func extractPCRs(attestation *attestpb.Attestation, indices []uint32) (map[uint32][]byte, error) {
	var sha256PCRs map[uint32][]byte
	for _, quote := range attestation.GetQuotes() {
		if quote.GetPcrs().GetHash() == tpmpb.HashAlgo_SHA256 {
			sha256PCRs = quote.GetPcrs().GetPcrs()
			break
		}
	}
	if sha256PCRs == nil {
		return nil, fmt.Errorf("no SHA-256 PCR quotes found")
	}

	result := make(map[uint32][]byte, len(indices))
	for _, idx := range indices {
		val, ok := sha256PCRs[idx]
		if !ok {
			return nil, fmt.Errorf("PCR %d not found", idx)
		}
		if len(val) != 32 {
			return nil, fmt.Errorf("PCR %d has invalid length: got %d, expected 32", idx, len(val))
		}
		result[idx] = val
	}
	return result, nil
}

func uploadToGCS(ctx context.Context, gcsURI string, data []byte) error {
	if len(gcsURI) < 6 || gcsURI[:5] != "gs://" {
		return fmt.Errorf("invalid GCS URI %q: must start with gs://", gcsURI)
	}
	rest := gcsURI[5:]
	slashIdx := bytes.IndexByte([]byte(rest), '/')
	if slashIdx < 0 {
		return fmt.Errorf("invalid GCS URI %q: missing object path", gcsURI)
	}
	bucket := rest[:slashIdx]
	object := rest[slashIdx+1:]

	token, err := getMetadataToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	url := fmt.Sprintf("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		bucket, object)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func getMetadataToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metadata HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from metadata server")
	}
	return tokenResp.AccessToken, nil
}
