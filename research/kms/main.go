// Package main implements a KMS server that verifies CVM attestations
// and releases secrets to verified workloads.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/go-tpm-tools/research/verifier"
)

// Config holds the KMS server configuration.
type Config struct {
	ListenAddr   string
	ContractAddr string
	EthRPCURL    string
}

// Server is the KMS HTTP server.
type Server struct {
	config Config
	client *ethclient.Client
	policy *PolicyChecker
}

// AttestRequest is the JSON request body for POST /v1/attest.
type AttestRequest struct {
	Attestation  []byte `json:"attestation"`
	RSAPublicKey string `json:"rsa_public_key"`
}

// AttestResponse is returned by POST /v1/attest.
type AttestResponse struct {
	Success         bool             `json:"success"`
	EncryptedSecret []byte           `json:"encrypted_secret,omitempty"`
	Error           string           `json:"error,omitempty"`
	Claims          *verifier.Claims `json:"claims,omitempty"`
}

func main() {
	config := Config{
		ListenAddr:   getEnv("LISTEN_ADDR", ":8080"),
		ContractAddr: getEnv("CONTRACT_ADDR", ""),
		EthRPCURL:    getEnv("ETH_RPC_URL", "http://127.0.0.1:8545"),
	}

	if config.ContractAddr == "" {
		log.Fatal("CONTRACT_ADDR environment variable required")
	}

	// Connect to Ethereum
	client, err := ethclient.Dial(config.EthRPCURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum: %v", err)
	}

	// Load contract
	contractAddr := common.HexToAddress(config.ContractAddr)
	contract, err := NewBaseImageAllowlist(contractAddr, client)
	if err != nil {
		log.Fatalf("Failed to load contract: %v", err)
	}

	// Initialize firmware verifier for MRTD validation against Google's TCB bucket
	ctx := context.Background()
	firmwareVerifier, err := NewFirmwareVerifier(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize firmware verifier: %v", err)
	}
	defer firmwareVerifier.Close()

	server := &Server{
		config: config,
		client: client,
		policy: NewPolicyChecker(firmwareVerifier, contract),
	}

	http.HandleFunc("/v1/attest", server.handleAttest)
	http.HandleFunc("/health", server.handleHealth)

	log.Printf("KMS server starting on %s", config.ListenAddr)
	log.Printf("Contract address: %s", config.ContractAddr)
	log.Printf("Ethereum RPC: %s", config.EthRPCURL)

	if err := http.ListenAndServe(config.ListenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleAttest handles attestation requests for both TDX and SEV-SNP.
// Uses server.VerifyAttestation() for TPM/AK validation.
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body: "+err.Error())
		return
	}

	if req.RSAPublicKey == "" {
		s.sendError(w, "RSA public key required")
		return
	}

	block, _ := pem.Decode([]byte(req.RSAPublicKey))
	if block == nil {
		s.sendError(w, "Invalid RSA public key PEM")
		return
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		s.sendError(w, "Failed to parse RSA public key: "+err.Error())
		return
	}

	rsaPubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		s.sendError(w, "Public key is not RSA")
		return
	}

	expectedRSAKeyHash := sha256.Sum256([]byte(req.RSAPublicKey))
	log.Printf("Verifying attestation with RSA key hash: %x", expectedRSAKeyHash)

	claims, err := verifier.Verify(req.Attestation, expectedRSAKeyHash[:])
	if err != nil {
		log.Printf("Attestation verification failed: %v", err)
		s.sendError(w, "Attestation verification failed: "+err.Error())
		return
	}

	log.Printf("Attestation verified (platform: %v)", claims.Platform)
	if claims.Container != nil {
		log.Printf("  Container: %s", claims.Container.ImageDigest)
	}
	if claims.GCE != nil {
		log.Printf("  GCE: %s/%s", claims.GCE.ProjectID, claims.GCE.InstanceName)
	}

	// Check policy (firmware endorsement, TCB, base image allowlist)
	if err := s.policy.Check(r.Context(), claims); err != nil {
		log.Printf("Policy check failed: %v", err)
		s.sendErrorWithClaims(w, err.Error(), claims)
		return
	}

	log.Printf("Policy checks passed! Releasing secret...")

	secret := []byte("test-secret-" + generateRandomString(8))
	encryptedSecret, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, secret, nil)
	if err != nil {
		log.Printf("Failed to encrypt secret: %v", err)
		s.sendError(w, "Failed to encrypt secret")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AttestResponse{
		Success:         true,
		EncryptedSecret: encryptedSecret,
		Claims:          claims,
	})
}

func (s *Server) sendError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(AttestResponse{Success: false, Error: msg})
}

func (s *Server) sendErrorWithClaims(w http.ResponseWriter, msg string, claims *verifier.Claims) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(AttestResponse{Success: false, Error: msg, Claims: claims})
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}
