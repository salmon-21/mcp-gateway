package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	dexapi "github.com/dexidp/dex/api/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// dexClientCreator is the subset of dexapi.DexClient we need. Narrowing the
// interface keeps the unit tests free of gRPC scaffolding.
type dexClientCreator interface {
	CreateClient(ctx context.Context, in *dexapi.CreateClientReq, opts ...grpc.CallOption) (*dexapi.CreateClientResp, error)
}

// DCR implements RFC 7591 Dynamic Client Registration by translating each
// request into a Dex CreateClient gRPC call.
type DCR struct {
	dex           dexClientCreator
	allowedScopes []string
	conn          *grpc.ClientConn
}

// NewDCR dials the Dex gRPC endpoint and returns a ready-to-serve handler.
// The connection is held until Close is called.
func NewDCR(grpcAddr string) (*DCR, error) {
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dex grpc dial: %w", err)
	}
	return &DCR{
		dex:           dexapi.NewDexClient(conn),
		allowedScopes: []string{"openid", "profile", "email", "offline_access"},
		conn:          conn,
	}, nil
}

func (h *DCR) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

type dcrRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// maxDCRBodyBytes caps the unauthenticated DCR request body to keep this
// endpoint from doubling as a DoS surface; a real RFC 7591 registration is
// well under 1 KiB.
const maxDCRBodyBytes = 64 << 10 // 64 KiB

func (h *DCR) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDCRBodyBytes)
	var req dcrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRegErr(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeRegErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}

	grantTypes := orDefaultSlice(req.GrantTypes, []string{"authorization_code"})
	responseTypes := orDefaultSlice(req.ResponseTypes, []string{"code"})
	if !subsetOf(grantTypes, []string{"authorization_code", "refresh_token"}) {
		writeRegErr(w, http.StatusBadRequest, "invalid_client_metadata",
			"only authorization_code and refresh_token grant types are supported")
		return
	}
	if !subsetOf(responseTypes, []string{"code"}) {
		writeRegErr(w, http.StatusBadRequest, "invalid_client_metadata",
			"only the code response type is supported")
		return
	}

	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}
	public := authMethod == "none"
	var secret string
	if !public {
		s, err := randomHex(32)
		if err != nil {
			writeRegErr(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		secret = s
	}

	id, err := randomHex(16)
	if err != nil {
		writeRegErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	clientID := "mcp-dcr-" + id

	resp, err := h.dex.CreateClient(r.Context(), &dexapi.CreateClientReq{
		Client: &dexapi.Client{
			Id:           clientID,
			Secret:       secret,
			RedirectUris: req.RedirectURIs,
			Name:         orDefault(req.ClientName, "Dynamically Registered"),
			LogoUrl:      req.LogoURI,
			Public:       public,
		},
	})
	if err != nil {
		slog.Error("dex CreateClient failed", "err", err)
		writeRegErr(w, http.StatusInternalServerError, "server_error", "upstream registration failed")
		return
	}
	if resp.GetAlreadyExists() {
		// Collision in the 32-hex space is astronomically unlikely; if it
		// happens, surfacing it is more honest than retrying silently.
		writeRegErr(w, http.StatusConflict, "invalid_client_metadata", "client id collision")
		return
	}

	out := dcrResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecret:            secret,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		Scope:                   intersectScopes(req.Scope, h.allowedScopes),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

func writeRegErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orDefaultSlice(s, def []string) []string {
	if len(s) == 0 {
		return def
	}
	return s
}

func subsetOf(a, allowed []string) bool {
	for _, v := range a {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}

// intersectScopes echoes back only those scopes the client requested that
// are also in the gateway's allow-list. Unknown scopes are silently dropped
// per RFC 6749 §3.3 (the AS MAY narrow scope).
func intersectScopes(requested string, allowed []string) string {
	if requested == "" {
		return strings.Join(allowed, " ")
	}
	want := strings.Fields(requested)
	out := make([]string, 0, len(want))
	for _, s := range want {
		if slices.Contains(allowed, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
