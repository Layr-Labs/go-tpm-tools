// Package main implements a simple KMS server that verifies TDX attestations
// and releases secrets to verified workloads.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Config holds the KMS server configuration.
type Config struct {
	ListenAddr   string
	ContractAddr string
	EthRPCURL    string
	NonceExpiry  time.Duration
}

// Server is the KMS HTTP server.
type Server struct {
	config   Config
	client   *ethclient.Client
	contract *BaseImageAllowlist
	nonces   map[string]time.Time
	mu       sync.RWMutex
}

// NonceResponse is returned by GET /v1/nonce.
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// AttestResponse is returned by POST /v1/attest.
type AttestResponse struct {
	Success bool                 `json:"success"`
	Secret  string               `json:"secret,omitempty"`
	Error   string               `json:"error,omitempty"`
	Claims  *VerifiedAttestation `json:"claims,omitempty"`
}

func main() {
	config := Config{
		ListenAddr:   getEnv("LISTEN_ADDR", ":8080"),
		ContractAddr: getEnv("CONTRACT_ADDR", ""),
		EthRPCURL:    getEnv("ETH_RPC_URL", "http://127.0.0.1:8545"),
		NonceExpiry:  5 * time.Minute,
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

	server := &Server{
		config:   config,
		client:   client,
		contract: contract,
		nonces:   make(map[string]time.Time),
	}

	// Start nonce cleanup goroutine
	go server.cleanupNonces()

	http.HandleFunc("/v1/nonce", server.handleNonce)
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

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate random nonce
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Store nonce with expiry
	s.mu.Lock()
	s.nonces[nonce] = time.Now().Add(s.config.NonceExpiry)
	s.mu.Unlock()

	log.Printf("Generated nonce: %s", nonce)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NonceResponse{Nonce: nonce})
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

	// Verify nonce was issued by us and hasn't expired
	nonceHex := hex.EncodeToString(req.Nonce)
	s.mu.Lock()
	expiry, exists := s.nonces[nonceHex]
	if exists {
		delete(s.nonces, nonceHex) // One-time use
	}
	s.mu.Unlock()

	if !exists {
		s.sendError(w, "Invalid or unknown nonce")
		return
	}
	if time.Now().After(expiry) {
		s.sendError(w, "Nonce expired")
		return
	}

	log.Printf("Verifying attestation with nonce: %s", nonceHex)

	// Verify the attestation
	claims, err := VerifyAttestation(&req)
	if err != nil {
		log.Printf("Attestation verification failed: %v", err)
		s.sendError(w, "Attestation verification failed: "+err.Error())
		return
	}

	log.Printf("Attestation verified successfully")
	log.Printf("  MRTD:  %x", claims.BaseImage.MRTD)
	log.Printf("  RTMR0: %x", claims.BaseImage.RTMR0)
	log.Printf("  RTMR1: %x", claims.BaseImage.RTMR1)
	log.Printf("  Container: %s", claims.Container.ImageDigest)
	if claims.GCE != nil {
		log.Printf("  GCE: %s/%s", claims.GCE.ProjectID, claims.GCE.InstanceName)
	}

	// Check if base image is allowed on-chain
	allowed, err := s.contract.IsAllowed(&bind.CallOpts{Context: context.Background()},
		claims.BaseImage.MRTD[:],
		claims.BaseImage.RTMR0[:],
		claims.BaseImage.RTMR1[:])
	if err != nil {
		log.Printf("Contract call failed: %v", err)
		s.sendError(w, "Failed to check allowlist: "+err.Error())
		return
	}

	if !allowed {
		log.Printf("Base image not in allowlist")
		log.Printf("  To add, run:")
		log.Printf("  cast send %s 'addBaseImage(bytes,bytes,bytes)' 0x%x 0x%x 0x%x --private-key $PRIVATE_KEY",
			s.config.ContractAddr, claims.BaseImage.MRTD, claims.BaseImage.RTMR0, claims.BaseImage.RTMR1)
		s.sendErrorWithClaims(w, "Base image not in allowlist", claims)
		return
	}

	log.Printf("Base image allowed! Releasing secret...")

	// Return test secret
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AttestResponse{
		Success: true,
		Secret:  "test-secret-" + generateRandomString(8),
		Claims:  claims,
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

func (s *Server) cleanupNonces() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for nonce, expiry := range s.nonces {
			if now.After(expiry) {
				delete(s.nonces, nonce)
			}
		}
		s.mu.Unlock()
	}
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
