package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryInjectsRegistrationEndpoint(t *testing.T) {
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("dex got unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"issuer": "https://gateway.example",
			"authorization_endpoint": "https://gateway.example/auth",
			"token_endpoint": "https://gateway.example/token",
			"jwks_uri": "https://gateway.example/keys"
		}`))
	}))
	defer dex.Close()

	d := NewDiscovery(dex.URL, "https://gateway.example")
	rr := httptest.NewRecorder()
	d.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if got["registration_endpoint"] != "https://gateway.example/oauth/register" {
		t.Errorf("registration_endpoint = %v, want gateway/oauth/register", got["registration_endpoint"])
	}
	if got["issuer"] != "https://gateway.example" {
		t.Errorf("issuer was clobbered: %v", got["issuer"])
	}
}

func TestProtectedResourceShape(t *testing.T) {
	h := ProtectedResource("https://gateway.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if got["resource"] != "https://gateway.example" {
		t.Errorf("resource = %v", got["resource"])
	}
	servers, _ := got["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != "https://gateway.example" {
		t.Errorf("authorization_servers = %v", servers)
	}
}
