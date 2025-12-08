// Package main implements a simple KMS server that verifies TDX attestations
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

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Config holds the KMS server configuration.
type Config struct {
	ListenAddr   string
	ContractAddr string
	EthRPCURL    string
}

// Server is the KMS HTTP server.
type Server struct {
	config           Config
	client           *ethclient.Client
	contract         *BaseImageAllowlist
	firmwareVerifier *FirmwareVerifier
}

// AttestResponse is returned by POST /v1/attest.
type AttestResponse struct {
	Success         bool                 `json:"success"`
	EncryptedSecret []byte               `json:"encrypted_secret,omitempty"`
	Error           string               `json:"error,omitempty"`
	Claims          *VerifiedAttestation `json:"claims,omitempty"`
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
		config:           config,
		client:           client,
		contract:         contract,
		firmwareVerifier: firmwareVerifier,
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

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RawAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body: "+err.Error())
		return
	}

	// Parse the client's RSA public key
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

	// Calculate expected RSA key hash = SHA256(RSA public key PEM)
	expectedRSAKeyHash := sha256.Sum256([]byte(req.RSAPublicKey))
	log.Printf("Verifying attestation with RSA key hash: %x", expectedRSAKeyHash)

	// Verify the attestation (including RSA key binding)
	claims, err := VerifyAttestation(&req, expectedRSAKeyHash[:])
	if err != nil {
		log.Printf("Attestation verification failed: %v", err)
		s.sendError(w, "Attestation verification failed: "+err.Error())
		return
	}

	log.Printf("Attestation verified successfully")

	// Log platform info (SVN and TD attributes)
	if claims.Platform != nil {
		log.Printf("  TCB SVN: %x", claims.Platform.TeeTcbSvn)
		log.Printf("  TD Attributes: Debug=%v, PerfMon=%v", claims.Platform.Attributes.Debug, claims.Platform.Attributes.PerfMon)
	}

	// WARNING: INSECURE CONFIGURATION
	// This demo only logs the container and GCE claims for visibility.
	// The real implementations MUST validate these claims as the existing KMS does.
	log.Printf("  MRTD:  %x", claims.BaseImage.MRTD)
	log.Printf("  RTMR0: %x", claims.BaseImage.RTMR0)
	log.Printf("  RTMR1: %x", claims.BaseImage.RTMR1)
	if claims.Firmware != nil {
		log.Printf("  Firmware: SecureBoot=%v, Hardened=%v", claims.Firmware.SecureBootEnabled, claims.Firmware.Hardened)
	}
	log.Printf("  Container: %s", claims.Container.ImageDigest)
	if claims.GCE != nil {
		log.Printf("  GCE: %s/%s", claims.GCE.ProjectID, claims.GCE.InstanceName)
	}

	// Check RTMR0 policy: Secure Boot must be enabled
	if claims.Firmware != nil && !claims.Firmware.SecureBootEnabled {
		log.Printf("Secure Boot is not enabled - rejecting")
		s.sendErrorWithClaims(w, "Secure Boot must be enabled", claims)
		return
	}

	// Verify MRTD (firmware) against Google's signed endorsements in GCS
	// This replaces the on-chain allowlist with cryptographic verification
	log.Printf("Verifying MRTD against Google's firmware endorsements...")
	firmwareEndorsement, err := s.firmwareVerifier.VerifyMRTD(r.Context(), claims.BaseImage.MRTD[:])
	if err != nil {
		log.Printf("Firmware verification failed: %v", err)
		s.sendErrorWithClaims(w, "Firmware not endorsed by Google: "+err.Error(), claims)
		return
	}
	log.Printf("  Firmware endorsed: SVN=%d, CL=%d, Built=%s", firmwareEndorsement.SVN, firmwareEndorsement.ClSpec, firmwareEndorsement.Timestamp.Format("2006-01-02"))

	// Check if RTMR1 (custom image) meets support level requirements
	imageAllowed, err := s.contract.IsImageAllowed(&bind.CallOpts{Context: context.Background()}, claims.BaseImage.RTMR1[:])
	if err != nil {
		log.Printf("Contract call failed: %v", err)
		s.sendError(w, "Failed to check image support level: "+err.Error())
		return
	}

	if !imageAllowed {
		// Get current support level for better error message
		supportLevel, _ := s.contract.GetImageSupport(&bind.CallOpts{Context: context.Background()}, claims.BaseImage.RTMR1[:])
		minLevel, _ := s.contract.MinimumSupportLevel(&bind.CallOpts{Context: context.Background()})
		supportLevelNames := []string{"NONE", "EXPERIMENTAL", "USABLE", "STABLE", "LATEST"}

		log.Printf("Image does not meet support level requirements")
		log.Printf("  Image support level: %s (%d)", supportLevelNames[supportLevel], supportLevel)
		log.Printf("  Minimum required: %s (%d)", supportLevelNames[minLevel], minLevel)
		log.Printf("  To add as LATEST, run:")
		log.Printf("  cast send %s 'setImageSupport(bytes,uint8)' 0x%x 4 --private-key $PRIVATE_KEY",
			s.config.ContractAddr, claims.BaseImage.RTMR1)
		s.sendErrorWithClaims(w, "Image does not meet support level requirements", claims)
		return
	}

	log.Printf("Base image allowed! Releasing secret...")

	// Generate and encrypt the secret with the client's RSA public key
	secret := []byte("test-secret-" + generateRandomString(8))
	encryptedSecret, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, secret, nil)
	if err != nil {
		log.Printf("Failed to encrypt secret: %v", err)
		s.sendError(w, "Failed to encrypt secret")
		return
	}

	log.Printf("Secret encrypted with client's RSA public key")

	// Return encrypted secret
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
	json.NewEncoder(w).Encode(AttestResponse{
		Success: false,
		Error:   msg,
	})
}

func (s *Server) sendErrorWithClaims(w http.ResponseWriter, msg string, claims *VerifiedAttestation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(AttestResponse{
		Success: false,
		Error:   msg,
		Claims:  claims,
	})
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
