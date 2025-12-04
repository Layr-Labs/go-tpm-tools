// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	gcaEndpoint       = "/v1/token"
	itaEndpoint       = "/v1/intel/token"
	rawAttestEndpoint = "/v1/raw-attestation"

	// Rate limiting: max requests per window
	maxRequestsPerWindow = 10
	rateLimitWindow      = time.Minute

	// Default nonce size for raw attestation
	defaultNonceSize = 32
)

var clientErrorCodes = map[codes.Code]struct{}{
	codes.InvalidArgument:    {},
	codes.FailedPrecondition: {},
	codes.PermissionDenied:   {},
	codes.Unauthenticated:    {},
	codes.NotFound:           {},
	codes.Aborted:            {},
	codes.OutOfRange:         {},
	codes.Canceled:           {},
}

// AttestClients contains clients for supported verifier services that can be used to
// get attestation tokens.
type AttestClients struct {
	GCA verifier.Client
	ITA verifier.Client
}

type attestHandler struct {
	ctx         context.Context
	attestAgent agent.AttestationAgent
	// defaultTokenFile string
	logger     logging.Logger
	launchSpec spec.LaunchSpec
	clients    AttestClients

	// Rate limiting
	rateMu       sync.Mutex
	requestCount int
	windowStart  time.Time
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger logging.Logger, launchSpec spec.LaunchSpec, clients AttestClients) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:         ctx,
				attestAgent: a,
				logger:      logger,
				launchSpec:  launchSpec,
				clients:     clients,
			}).Handler(),
		},
	}
	return &teeServer, nil
}

// Handler creates a multiplexer for the server.
func (a *attestHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	// to test default token: curl --unix-socket <socket> http://localhost/v1/token
	// to test custom token:
	// curl -d '{"audience":"<aud>", "nonces":["<nonce1>"]}' -H "Content-Type: application/json" -X POST
	//   --unix-socket /tmp/container_launcher/teeserver.sock http://localhost/v1/token

	mux.HandleFunc(gcaEndpoint, a.getToken)
	mux.HandleFunc(itaEndpoint, a.getITAToken)
	mux.HandleFunc(rawAttestEndpoint, a.getRawAttestation)
	return mux
}

func (a *attestHandler) logAndWriteError(errStr string, status int, w http.ResponseWriter) {
	a.logger.Error(errStr)
	w.WriteHeader(status)
	w.Write([]byte(errStr))
}

// checkRateLimit returns true if the request is allowed, false if rate limited.
func (a *attestHandler) checkRateLimit() bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()

	now := time.Now()
	if now.Sub(a.windowStart) >= rateLimitWindow {
		// Reset window
		a.windowStart = now
		a.requestCount = 1
		return true
	}

	if a.requestCount >= maxRequestsPerWindow {
		return false
	}

	a.requestCount++
	return true
}

// getDefaultToken handles the request to get the default OIDC token.
// For now this function will just read the content of the file and return.
// Later, this function can use attestation agent to get a token directly.
func (a *attestHandler) getToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	a.logger.Info(fmt.Sprintf("%s called", gcaEndpoint))

	// If the handler does not have an GCA client, return error.
	if a.clients.GCA == nil {
		errStr := "no GCA verifier client present, please try rebooting your VM"
		a.logAndWriteError(errStr, http.StatusInternalServerError, w)
		return
	}

	a.attest(w, r, a.clients.GCA)
}

// getITAToken retrieves a attestation token signed by ITA.
func (a *attestHandler) getITAToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	a.logger.Info(fmt.Sprintf("%s called", itaEndpoint))

	// If the handler does not have an ITA client, return error.
	if a.clients.ITA == nil {
		errStr := "no ITA verifier client present - ensure ITA Region and Key are defined in metadata"
		a.logAndWriteError(errStr, http.StatusInternalServerError, w)
		return
	}

	a.attest(w, r, a.clients.ITA)
}

// rawAttestRequest is the optional request body for /v1/raw-attestation
type rawAttestRequest struct {
	Nonce []byte `json:"nonce,omitempty"`
}

// rawAttestResponse is the response body for /v1/raw-attestation
type rawAttestResponse struct {
	TdQuote       []byte   `json:"td_quote"`
	CEL           []byte   `json:"cel"`
	CcelAcpiTable []byte   `json:"ccel_acpi_table"`
	CcelData      []byte   `json:"ccel_data"`
	Nonce         []byte   `json:"nonce"`
	AkCertChain   [][]byte `json:"ak_cert_chain,omitempty"` // AK cert + intermediate certs (DER encoded)
}

// getRawAttestation returns the raw TDX quote and CEL for self-verification.
// This allows relying parties to verify the quote against Intel's root CA
// and replay the CEL to extract container claims without requiring Google RIM validation.
func (a *attestHandler) getRawAttestation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	a.logger.Info(fmt.Sprintf("%s called", rawAttestEndpoint))

	if !a.checkRateLimit() {
		a.logAndWriteHTTPError(w, http.StatusTooManyRequests, fmt.Errorf("rate limit exceeded: max %d requests per %v", maxRequestsPerWindow, rateLimitWindow))
		return
	}

	var nonce []byte

	switch r.Method {
	case http.MethodGet:
		// Generate random nonce
		nonce = make([]byte, defaultNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate nonce: %w", err))
			return
		}

	case http.MethodPost:
		var req rawAttestRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to parse request body: %w", err))
			return
		}
		if len(req.Nonce) == 0 {
			// Generate random nonce if not provided
			nonce = make([]byte, defaultNonceSize)
			if _, err := rand.Read(nonce); err != nil {
				a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate nonce: %w", err))
				return
			}
		} else {
			nonce = req.Nonce
		}

	default:
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}

	// Get raw attestation from the agent
	rawAttest, err := a.attestAgent.GetRawAttestation(nonce)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to get raw attestation: %w", err))
		return
	}

	resp := rawAttestResponse{
		TdQuote:       rawAttest.TdQuote,
		CEL:           rawAttest.CEL,
		CcelAcpiTable: rawAttest.CcelAcpiTable,
		CcelData:      rawAttest.CcelData,
		Nonce:         nonce,
		AkCertChain:   rawAttest.AkCertChain,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		a.logger.Error(fmt.Sprintf("failed to encode response: %v", err))
	}
}

func (a *attestHandler) attest(w http.ResponseWriter, r *http.Request, client verifier.Client) {
	if !a.checkRateLimit() {
		a.logAndWriteHTTPError(w, http.StatusTooManyRequests, fmt.Errorf("rate limit exceeded: max %d requests per %v", maxRequestsPerWindow, rateLimitWindow))
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := a.attestAgent.Refresh(a.ctx); err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to refresh attestation agent: %w", err))
			return
		}

		token, err := a.attestAgent.AttestWithClient(a.ctx, agent.AttestAgentOpts{}, client)
		if err != nil {
			a.handleAttestError(w, err, "failed to retrieve attestation service token")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(token)
		return

	case http.MethodPost:
		var tokenOptions models.TokenOptions
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&tokenOptions)
		if err != nil {
			err = fmt.Errorf("failed to parse POST body as TokenOptions: %v", err)
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		if tokenOptions.Audience == "" {
			err := fmt.Errorf("use GET request for the default identity token")
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		if tokenOptions.TokenType == "" {
			err := fmt.Errorf("token_type is a required parameter")
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		// Do not check that TokenTypeOptions matches TokenType in the launcher.
		opts := agent.AttestAgentOpts{
			TokenOptions: &tokenOptions,
		}
		tok, err := a.attestAgent.AttestWithClient(a.ctx, opts, client)
		if err != nil {
			a.handleAttestError(w, err, "failed to retrieve custom attestation service token")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(tok)
		return
	default:
		// TODO: add an url pointing to the REST API document
		err := fmt.Errorf("TEE server received an invalid HTTP method: %s", r.Method)
		a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
	}
}

func (a *attestHandler) logAndWriteHTTPError(w http.ResponseWriter, statusCode int, err error) {
	a.logger.Error(err.Error())
	w.WriteHeader(statusCode)
	w.Write([]byte(err.Error()))
}

// Serve starts the server, will block until the server shutdown.
func (s *TeeServer) Serve() error {
	return s.server.Serve(s.netListener)
}

// Shutdown will terminate the server and the underlying listener.
func (s *TeeServer) Shutdown(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	err2 := s.netListener.Close()

	if err != nil {
		return err
	}
	if err2 != nil {
		return err2
	}
	return nil
}

func (a *attestHandler) handleAttestError(w http.ResponseWriter, err error, message string) {
	st, ok := status.FromError(err)
	if ok {
		if _, exists := clientErrorCodes[st.Code()]; exists {
			// User errors, like invalid arguments. Map user errors to 400 Bad Request.
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("%s: %w", message, err))
			return
		}
		// Server-side or transient errors. Map user errors 500 Internal Server Error.
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
		return
	}
	// If it's not a gRPC error, it's likely an internal error within the launcher.
	// Map user errors 500 Internal Server Error
	a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
}
