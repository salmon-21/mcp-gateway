package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dexapi "github.com/dexidp/dex/api/v2"
	"google.golang.org/grpc"
)

type fakeDex struct {
	gotReq *dexapi.CreateClientReq
	resp   *dexapi.CreateClientResp
	err    error
}

func (f *fakeDex) CreateClient(ctx context.Context, in *dexapi.CreateClientReq, opts ...grpc.CallOption) (*dexapi.CreateClientResp, error) {
	f.gotReq = in
	if f.resp != nil {
		return f.resp, nil
	}
	return &dexapi.CreateClientResp{Client: in.Client}, f.err
}

func newHandler(d dexClientCreator) *DCR {
	return &DCR{
		dex:           d,
		allowedScopes: []string{"openid", "profile", "email", "offline_access"},
	}
}

func TestDCRPublicClientFlow(t *testing.T) {
	dex := &fakeDex{}
	h := newHandler(dex)

	body := `{
		"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
		"client_name": "Claude",
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"scope": "openid profile email offline_access mystery"
	}`
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp dcrResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !strings.HasPrefix(resp.ClientID, "mcp-dcr-") {
		t.Errorf("client_id = %q, want mcp-dcr- prefix", resp.ClientID)
	}
	if resp.ClientSecret != "" {
		t.Errorf("public client should not get a secret, got %q", resp.ClientSecret)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q", resp.TokenEndpointAuthMethod)
	}
	if resp.Scope != "openid profile email offline_access" {
		t.Errorf("scope = %q, want unknown ‘mystery’ dropped", resp.Scope)
	}
	if dex.gotReq.Client.Id != resp.ClientID {
		t.Errorf("dex got id %q, want %q", dex.gotReq.Client.Id, resp.ClientID)
	}
	if !dex.gotReq.Client.Public {
		t.Errorf("public flag should be set on the Dex client")
	}
}

func TestDCRRejectsBadGrant(t *testing.T) {
	h := newHandler(&fakeDex{})
	r := httptest.NewRequest(http.MethodPost, "/oauth/register",
		strings.NewReader(`{"redirect_uris":["https://x"],"grant_types":["password"]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestDCRRejectsMissingRedirect(t *testing.T) {
	h := newHandler(&fakeDex{})
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestDCRConfidentialClientGetsSecret(t *testing.T) {
	h := newHandler(&fakeDex{})
	r := httptest.NewRequest(http.MethodPost, "/oauth/register",
		strings.NewReader(`{"redirect_uris":["https://x"],"token_endpoint_auth_method":"client_secret_basic"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ClientSecret == "" {
		t.Errorf("confidential client should get a secret")
	}
}
