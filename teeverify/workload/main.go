// Workload captures attestation test vectors from Confidential Space VMs.
//
// It runs inside the VM, connects to the TEE server socket, generates
// attestation vectors, and serves them over HTTP on port 8080 for retrieval.
//
// Usage:
//
//	HARDENED=true workload -socket /run/container_launcher/teeserver.sock
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

type testVector struct {
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Hardened    bool   `json:"hardened"`
	Attestation string `json:"attestation"` // base64
	Challenge   string `json:"challenge"`   // hex
	ExtraData   string `json:"extra_data"`  // hex
}

func main() {
	socket := flag.String("socket", "/run/container_launcher/teeserver.sock", "TEE server Unix socket path")
	flag.Parse()

	// Read hardened flag from HARDENED env var (set via tee-env-HARDENED metadata).
	hardened := os.Getenv("HARDENED") == "true"

	// Wait for TEE server socket.
	fmt.Fprintf(os.Stderr, "waiting for TEE server socket at %s\n", *socket)
	if err := waitForSocket(*socket, 60*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *socket)
			},
		},
		Timeout: 30 * time.Second,
	}

	type vectorSpec struct {
		label     string
		challenge []byte
		extraData []byte
	}

	// Generate challenge bytes.
	challenge1 := make([]byte, 32)
	challenge2 := make([]byte, 32)
	extraData := make([]byte, 32)
	mustRand(challenge1)
	mustRand(challenge2)
	mustRand(extraData)

	specs := []vectorSpec{
		{label: "no extra data", challenge: challenge1, extraData: nil},
		{label: "with extra data", challenge: challenge2, extraData: extraData},
	}

	var vectors []testVector
	for _, spec := range specs {
		fmt.Fprintf(os.Stderr, "capturing: %s\n", spec.label)

		attestBytes, err := fetchAttestation(client, spec.challenge, spec.extraData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching attestation for %q: %v\n", spec.label, err)
			os.Exit(1)
		}

		platform := detectPlatform(attestBytes)
		mode := "debug"
		if hardened {
			mode = "hardened"
		}
		name := fmt.Sprintf("%s - %s - %s", platformName(platform), mode, spec.label)

		ed := ""
		if len(spec.extraData) > 0 {
			ed = hex.EncodeToString(spec.extraData)
		}

		vectors = append(vectors, testVector{
			Name:        name,
			Platform:    platform,
			Hardened:    hardened,
			Attestation: base64.StdEncoding.EncodeToString(attestBytes),
			Challenge:   hex.EncodeToString(spec.challenge),
			ExtraData:   ed,
		})
	}

	out, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling output: %v\n", err)
		os.Exit(1)
	}

	// Upload to GCS if GCS_OUTPUT is set (e.g. gs://bucket/path/vectors.json).
	// This is the primary retrieval method for hardened images that block SSH.
	if gcsURI := os.Getenv("GCS_OUTPUT"); gcsURI != "" {
		fmt.Fprintf(os.Stderr, "uploading vectors to %s\n", gcsURI)
		if err := uploadToGCS(context.Background(), gcsURI, out); err != nil {
			fmt.Fprintf(os.Stderr, "GCS upload failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "GCS upload succeeded\n")
	}

	// Serve vectors over HTTP as a fallback (useful for debug images with SSH).
	fmt.Fprintf(os.Stderr, "serving %d vectors on :8080/vectors\n", len(vectors))
	http.HandleFunc("/vectors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
		os.Exit(1)
	}
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

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintf(os.Stderr, "crypto/rand failed: %v\n", err)
		os.Exit(1)
	}
}

type boundEvidenceRequest struct {
	Challenge string `json:"challenge"`  // base64
	ExtraData string `json:"extra_data"` // base64
}

func fetchAttestation(client *http.Client, challenge, extraData []byte) ([]byte, error) {
	reqBody := boundEvidenceRequest{
		Challenge: base64.StdEncoding.EncodeToString(challenge),
	}
	if len(extraData) > 0 {
		reqBody.ExtraData = base64.StdEncoding.EncodeToString(extraData)
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := client.Post("http://localhost/v1/bound_evidence", "application/json", bytes.NewReader(body))
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

func detectPlatform(attestBytes []byte) string {
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestBytes, &attestation); err != nil {
		return "unknown"
	}
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

func platformName(platform string) string {
	switch platform {
	case "intel_tdx":
		return "Intel TDX"
	case "amd_sev_snp":
		return "AMD SEV-SNP"
	case "gcp_shielded_vm":
		return "GCP Shielded VM"
	default:
		return "Unknown"
	}
}

// uploadToGCS uploads data to a GCS object specified by a gs:// URI.
// It uses the metadata server to get an access token (no SDK needed).
func uploadToGCS(ctx context.Context, gcsURI string, data []byte) error {
	// Parse gs://bucket/object/path
	if !strings.HasPrefix(gcsURI, "gs://") {
		return fmt.Errorf("invalid GCS URI %q: must start with gs://", gcsURI)
	}
	rest := gcsURI[len("gs://"):]
	slashIdx := strings.Index(rest, "/")
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

// getMetadataToken fetches an access token from the GCE metadata server.
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
