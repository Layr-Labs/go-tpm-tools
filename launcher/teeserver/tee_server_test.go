package teeserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/cel"
	"github.com/Layr-Labs/go-tpm-tools/launcher/agent"
	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
	"github.com/Layr-Labs/go-tpm-tools/launcher/spec"
	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	"github.com/Layr-Labs/go-tpm-tools/verifier"
	"github.com/Layr-Labs/go-tpm-tools/verifier/models"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Implements verifier.Client interface so it can be used to initialize test attestHandlers
type fakeVerifierClient struct{}

func (f *fakeVerifierClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyAttestation(_ context.Context, _ verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyConfidentialSpace(_ context.Context, _ verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

type fakeAttestationAgent struct {
	measureEventFunc             func(cel.Content) error
	attestFunc                   func(context.Context, agent.AttestAgentOpts) ([]byte, error)
	attestWithClientFunc         func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error)
	boundAttestationEvidenceFunc func(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error)
}

func (f fakeAttestationAgent) Attest(c context.Context, a agent.AttestAgentOpts) ([]byte, error) {
	return f.attestFunc(c, a)
}

func (f fakeAttestationAgent) AttestWithClient(c context.Context, a agent.AttestAgentOpts, v verifier.Client) ([]byte, error) {
	return f.attestWithClientFunc(c, a, v)
}

func (f fakeAttestationAgent) MeasureEvent(c cel.Content) error {
	return f.measureEventFunc(c)
}

func (f fakeAttestationAgent) Refresh(_ context.Context) error {
	return nil
}

func (f fakeAttestationAgent) Close() error {
	return nil
}

func (f fakeAttestationAgent) BoundAttestationEvidence(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
	if f.boundAttestationEvidenceFunc != nil {
		return f.boundAttestationEvidenceFunc(opts)
	}
	return nil, fmt.Errorf("unimplemented")
}

func TestGetDefaultToken(t *testing.T) {
	testTokenContent := "test token"

	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: AttestClients{
			GCA: &fakeVerifierClient{},
		},
		attestAgent: fakeAttestationAgent{
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte(testTokenContent), nil
			},
		}}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()

	ah.getToken(w, req)
	data, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusOK)
	}
	if diff := cmp.Diff(testTokenContent, string(data)); diff != "" {
		t.Errorf("getToken() response body mismatch (-want +got):\n%s", diff)
	}
}

func TestGetDefaultTokenServerError(t *testing.T) {
	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: AttestClients{
			GCA: &fakeVerifierClient{},
		},
		attestAgent: fakeAttestationAgent{
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return nil, errors.New("internal server error from agent")
			},
		}}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()

	ah.getToken(w, req)
	data, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusInternalServerError)
	}
	expectedError := "failed to retrieve attestation service token: internal server error from agent"
	if diff := cmp.Diff(expectedError, string(data)); diff != "" {
		t.Errorf("getToken() response body mismatch (-want +got):\n%s", diff)
	}
}

func TestCustomToken(t *testing.T) {
	tests := []struct {
		testName             string
		body                 string
		attestWithClientFunc func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error)
		want                 int
	}{
		{
			testName: "TestNoAudiencePostRequest",
			body: `{
				"audience": "",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
				}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				t.Errorf("This method should not be called")
				return nil, nil
			},
			want: http.StatusBadRequest,
		},
		{
			testName: "TestRequestFailurePassedToCaller",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return nil, errors.New("Error")
			},
			want: http.StatusInternalServerError,
		},
		{
			testName: "TestTokenTypeRequired",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": ""
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				t.Errorf("This method should not be called")
				return nil, nil
			},
			want: http.StatusBadRequest,
		},
		{
			testName: "TestRequestSuccessPassedToCaller",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
		{
			testName: "TestPrincipalTagOptionsSuccess",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
						"container_image_signatures" : {
							"key_ids": ["test1", "test2"]
						}
					}
				}
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
	}

	verifiers := []struct {
		name        string
		url         string
		tokenMethod func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:        "GCA Handler",
			url:         "/v1/token",
			tokenMethod: (*attestHandler).getToken,
		},
		{
			name:        "ITA Handler",
			url:         "/v1/intel/token",
			tokenMethod: (*attestHandler).getITAToken,
		},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			for _, test := range tests {
				ah := attestHandler{
					logger: logging.SimpleLogger(),
					clients: AttestClients{
						GCA: &fakeVerifierClient{},
						ITA: &fakeVerifierClient{},
					},
					attestAgent: fakeAttestationAgent{
						attestWithClientFunc: test.attestWithClientFunc,
					}}

				b := strings.NewReader(test.body)

				req := httptest.NewRequest(http.MethodPost, vf.url, b)
				w := httptest.NewRecorder()

				vf.tokenMethod(&ah, w, req)

				_, err := io.ReadAll(w.Result().Body)
				if err != nil {
					t.Error(err)
				}

				if w.Code != test.want {
					t.Errorf("testcase '%v': got return code: %d, want: %d", test.testName, w.Code, test.want)
				}
			}
		})
	}
}

func TestHandleAttestError(t *testing.T) {
	body := `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`

	errorCases := []struct {
		name           string
		err            error
		wantStatusCode int
	}{
		{
			name:           "FailedPrecondition error",
			err:            status.New(codes.FailedPrecondition, "bad state").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "PermissionDenied error",
			err:            status.New(codes.PermissionDenied, "denied").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "Internal error",
			err:            status.New(codes.Internal, "internal server error").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "Unavailable error",
			err:            status.New(codes.Unavailable, "service unavailable").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "non-gRPC error",
			err:            errors.New("a generic error"),
			wantStatusCode: http.StatusInternalServerError,
		},
	}

	verifiers := []struct {
		name        string
		url         string
		tokenMethod func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:        "GCA Handler",
			url:         "/v1/token",
			tokenMethod: (*attestHandler).getToken,
		},
		{
			name:        "ITA Handler",
			url:         "/v1/intel/token",
			tokenMethod: (*attestHandler).getITAToken,
		},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			for _, tc := range errorCases {
				t.Run(tc.name, func(t *testing.T) {
					ah := attestHandler{
						logger: logging.SimpleLogger(),
						clients: AttestClients{
							GCA: &fakeVerifierClient{},
							ITA: &fakeVerifierClient{},
						},
						attestAgent: fakeAttestationAgent{
							attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
								return nil, tc.err
							},
						},
					}

					req := httptest.NewRequest(http.MethodPost, vf.url, strings.NewReader(body))
					w := httptest.NewRecorder()

					vf.tokenMethod(&ah, w, req)

					if w.Code != tc.wantStatusCode {
						t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
					}

					_, err := io.ReadAll(w.Result().Body)
					if err != nil {
						t.Errorf("failed to read response body: %v", err)
					}
				})
			}
		})
	}
}

func TestHandleAttestError_NilClient(t *testing.T) {
	verifiers := []struct {
		name    string
		url     string
		handler func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{name: "GCA Handler", url: "/v1/token", handler: (*attestHandler).getToken},
		{name: "ITA Handler", url: "/v1/intel/token", handler: (*attestHandler).getITAToken},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			ah := attestHandler{
				logger:  logging.SimpleLogger(),
				clients: AttestClients{}, // No clients defined
			}

			req := httptest.NewRequest(http.MethodPost, vf.url, strings.NewReader(""))
			w := httptest.NewRecorder()
			vf.handler(&ah, w, req)

			const wantStatusCode = http.StatusInternalServerError
			if w.Code != wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, wantStatusCode)
			}
		})
	}
}

func TestCustomTokenDataParsedSuccessfully(t *testing.T) {
	tests := []struct {
		testName   string
		body       string
		attestFunc func(context.Context, agent.AttestAgentOpts) ([]byte, error)
		wantCode   int
		wantOpts   agent.AttestAgentOpts
	}{
		{
			testName: "TestKeyIdsReadSuccessfullyEvenWithInvalidTokenTypeMatch",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
						"container_image_signatures" : {
							"key_ids": ["test1", "test2"]
						}
					}
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{
							ContainerImageSignatures: &models.ContainerImageSignatures{
								KeyIDs: []string{"test1", "test2"},
							},
						},
					},
				},
			},
		},
		{
			testName: "PartialAwsPrincipalTagOptionsOK",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:            "audience",
					Nonces:              []string{"thisIsAcustomNonce"},
					TokenType:           "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{},
				},
			},
		},
		{
			testName: "MorePartialAwsPrincipalTagOptionsOK",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
					}
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{},
					},
				},
			},
		},
		{
			testName: "InvalidJSONNotOkay",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tag": {
					}
				}
			}`,
			wantCode: http.StatusBadRequest,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{},
					},
				},
			},
		},
	}

	for i, test := range tests {
		ah := attestHandler{
			logger: logging.SimpleLogger(),
			clients: AttestClients{
				GCA: &fakeVerifierClient{},
			},
			attestAgent: fakeAttestationAgent{
				attestWithClientFunc: func(_ context.Context, gotOpts agent.AttestAgentOpts, _ verifier.Client) ([]byte, error) {
					diff := cmp.Diff(test.wantOpts, gotOpts)
					if diff != "" {
						t.Errorf("%v: got unexpected agent.AttestAgentOpts. diff:\n%v", test.testName, diff)
					}
					return []byte{}, nil
				},
			}}

		b := strings.NewReader(test.body)

		req := httptest.NewRequest(http.MethodPost, "/v1/token", b)
		w := httptest.NewRecorder()
		ah.getToken(w, req)
		_, err := io.ReadAll(w.Result().Body)
		if err != nil {
			t.Error(err)
		}

		if w.Code != test.wantCode {
			t.Errorf("testcase %d, '%v': got return code: %d, want: %d", i, test.testName, w.Code, test.wantCode)
		}
	}
}

func TestCustomHandleAttestError(t *testing.T) {
	body := `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`

	testcases := []struct {
		name           string
		err            error
		wantStatusCode int
	}{
		{
			name:           "FailedPrecondition error",
			err:            status.New(codes.FailedPrecondition, "bad state").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "PermissionDenied error",
			err:            status.New(codes.PermissionDenied, "denied").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "Internal error",
			err:            status.New(codes.Internal, "internal server error").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "Unavailable error",
			err:            status.New(codes.Unavailable, "service unavailable").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "non-gRPC error",
			err:            errors.New("a generic error"),
			wantStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ah := attestHandler{
				logger: logging.SimpleLogger(),
				clients: AttestClients{
					GCA: &fakeVerifierClient{},
				},
				attestAgent: fakeAttestationAgent{
					attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
						return nil, tc.err
					},
				},
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/token", strings.NewReader(body))
			w := httptest.NewRecorder()

			ah.getToken(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
			}

			_, err := io.ReadAll(w.Result().Body)
			if err != nil {
				t.Errorf("failed to read response body: %v", err)
			}
		})
	}
}

func TestGetAttestation(t *testing.T) {
	testChallenge := []byte("testnonce12345678")
	testExtraData := []byte("userdata")
	testAttestation := &attestpb.Attestation{
		AkPub: []byte("test-ak-pub"),
	}

	testCases := []struct {
		name           string
		body           string
		wantStatusCode int
		wantChallenge  []byte
		wantExtraData  []byte
	}{
		{
			name:           "success with challenge only",
			body:           fmt.Sprintf(`{"challenge":"%s"}`, base64.StdEncoding.EncodeToString(testChallenge)),
			wantStatusCode: http.StatusOK,
			wantChallenge:  testChallenge,
			wantExtraData:  nil,
		},
		{
			name:           "success with challenge and extra_data",
			body:           fmt.Sprintf(`{"challenge":"%s","extra_data":"%s"}`, base64.StdEncoding.EncodeToString(testChallenge), base64.StdEncoding.EncodeToString(testExtraData)),
			wantStatusCode: http.StatusOK,
			wantChallenge:  testChallenge,
			wantExtraData:  testExtraData,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var receivedOpts agent.BoundAttestationOpts
			ah := attestHandler{
				ctx:        context.Background(),
				logger:     logging.SimpleLogger(),
				launchSpec: spec.LaunchSpec{SelfVerificationEnabled: true},
				attestAgent: fakeAttestationAgent{
					boundAttestationEvidenceFunc: func(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
						receivedOpts = opts
						return testAttestation, nil
					},
				},
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/bound_evidence", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			ah.getBoundEvidence(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
			}

			if tc.wantStatusCode == http.StatusOK {
				// Verify challenge and extraData were passed correctly
				if diff := cmp.Diff(tc.wantChallenge, receivedOpts.Challenge); diff != "" {
					t.Errorf("challenge mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(tc.wantExtraData, receivedOpts.ExtraData); diff != "" {
					t.Errorf("extraData mismatch (-want +got):\n%s", diff)
				}

				// Verify response can be unmarshaled as Attestation proto
				body, err := io.ReadAll(w.Result().Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}

				var gotAttestation attestpb.Attestation
				if err := proto.Unmarshal(body, &gotAttestation); err != nil {
					t.Fatalf("failed to unmarshal response as Attestation: %v", err)
				}

				if diff := cmp.Diff(testAttestation.AkPub, gotAttestation.AkPub); diff != "" {
					t.Errorf("attestation mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestGetAttestationErrors(t *testing.T) {
	testAttestation := &attestpb.Attestation{AkPub: []byte("test-ak-pub")}
	validChallenge := base64.StdEncoding.EncodeToString([]byte("testnonce"))

	testCases := []struct {
		name                    string
		selfVerificationEnabled bool
		method                  string
		body                    string
		agentErr                error
		wantStatusCode          int
		wantBodyContains        string
	}{
		{
			name:                    "self-verification disabled",
			selfVerificationEnabled: false,
			method:                  http.MethodPost,
			body:                    fmt.Sprintf(`{"challenge":"%s"}`, validChallenge),
			wantStatusCode:          http.StatusNotFound,
			wantBodyContains:        "self-verification not enabled",
		},
		{
			name:                    "wrong HTTP method GET",
			selfVerificationEnabled: true,
			method:                  http.MethodGet,
			body:                    "",
			wantStatusCode:          http.StatusMethodNotAllowed,
			wantBodyContains:        "method GET not allowed",
		},
		{
			name:                    "wrong HTTP method PUT",
			selfVerificationEnabled: true,
			method:                  http.MethodPut,
			body:                    fmt.Sprintf(`{"challenge":"%s"}`, validChallenge),
			wantStatusCode:          http.StatusMethodNotAllowed,
			wantBodyContains:        "method PUT not allowed",
		},
		{
			name:                    "empty request body",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    "",
			wantStatusCode:          http.StatusBadRequest,
			wantBodyContains:        "failed to parse request body",
		},
		{
			name:                    "missing challenge",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    `{}`,
			wantStatusCode:          http.StatusBadRequest,
			wantBodyContains:        "challenge is required",
		},
		{
			name:                    "empty challenge",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    `{"challenge":""}`,
			wantStatusCode:          http.StatusBadRequest,
			wantBodyContains:        "challenge is required",
		},
		{
			name:                    "invalid JSON",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    `{invalid json`,
			wantStatusCode:          http.StatusBadRequest,
			wantBodyContains:        "failed to parse request body",
		},
		{
			name:                    "unknown JSON field",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    fmt.Sprintf(`{"challenge":"%s","unknown_field":"value"}`, validChallenge),
			wantStatusCode:          http.StatusBadRequest,
			wantBodyContains:        "failed to parse request body",
		},
		{
			name:                    "agent returns error",
			selfVerificationEnabled: true,
			method:                  http.MethodPost,
			body:                    fmt.Sprintf(`{"challenge":"%s"}`, validChallenge),
			agentErr:                errors.New("TEE device not available"),
			wantStatusCode:          http.StatusInternalServerError,
			wantBodyContains:        "failed to get attestation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ah := attestHandler{
				ctx:        context.Background(),
				logger:     logging.SimpleLogger(),
				launchSpec: spec.LaunchSpec{SelfVerificationEnabled: tc.selfVerificationEnabled},
				attestAgent: fakeAttestationAgent{
					boundAttestationEvidenceFunc: func(_ agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
						if tc.agentErr != nil {
							return nil, tc.agentErr
						}
						return testAttestation, nil
					},
				},
			}

			req := httptest.NewRequest(tc.method, "/v1/bound_evidence", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			ah.getBoundEvidence(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
			}

			body, err := io.ReadAll(w.Result().Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			if !strings.Contains(string(body), tc.wantBodyContains) {
				t.Errorf("response body %q does not contain %q", string(body), tc.wantBodyContains)
			}
		})
	}
}
