package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"valid", "Bearer abc123", "abc123", true},
		{"empty after prefix", "Bearer ", "", false},
		{"whitespace only after prefix", "Bearer   ", "", false},
		{"missing prefix", "abc123", "", false},
		{"wrong prefix", "Basic abc", "", false},
		{"empty header", "", "", false},
		{"lowercase prefix", "bearer abc", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got, ok := extractBearer(r)
			if ok != c.ok || got != c.want {
				t.Errorf("extractBearer(%q) = (%q, %v), want (%q, %v)", c.header, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestAudienceMatches(t *testing.T) {
	v := &Verifier{allowedAud: []string{"mcp", "other"}}
	cases := []struct {
		name string
		aud  []string
		want bool
	}{
		{"single match", []string{"mcp"}, true},
		{"second match", []string{"other"}, true},
		{"no match", []string{"foreign"}, false},
		{"empty", []string{}, false},
		{"multi with one match", []string{"foreign", "mcp"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := v.audienceMatches(c.aud); got != c.want {
				t.Errorf("audienceMatches(%v) = %v, want %v", c.aud, got, c.want)
			}
		})
	}
}

func TestMiddlewareEmits401WithWWWAuthenticate(t *testing.T) {
	v := &Verifier{} // allowedAud empty → no audience check, no provider needed
	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	})
	h := v.Middleware("https://gateway.example")(next)

	cases := []struct {
		name   string
		header string
	}{
		{"missing", ""},
		{"empty bearer", "Bearer "},
		{"wrong prefix", "Token abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called = false
			r := httptest.NewRequest(http.MethodGet, "/mcp/x", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			ww := rr.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(ww, "Bearer ") {
				t.Errorf("WWW-Authenticate must start with Bearer, got %q", ww)
			}
			if !strings.Contains(ww, `resource_metadata="https://gateway.example/.well-known/oauth-protected-resource"`) {
				t.Errorf("resource_metadata missing or wrong: %q", ww)
			}
			if !strings.Contains(ww, `scope="openid profile email offline_access"`) {
				t.Errorf("scope missing from challenge: %q", ww)
			}
			// No credential was supplied, so RFC 6750 §3 says the challenge
			// must not claim the token was invalid.
			if strings.Contains(ww, "error=") {
				t.Errorf("bare challenge must not carry error=: %q", ww)
			}
			if called {
				t.Error("next handler must not run on auth failure")
			}
		})
	}
}

func TestMiddlewareInvalidJWTReturns401(t *testing.T) {
	// A bogus token still fails go-oidc verify, hitting the 401 path with the
	// underlying error in error_description.
	provider := startBogusProvider(t)
	defer provider.Close()
	v, err := NewVerifier(context.Background(), provider.URL, "https://gateway.example", nil, 0)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	h := v.Middleware("https://gateway.example")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next must not be called for an invalid token")
	}))
	r := httptest.NewRequest(http.MethodGet, "/mcp/x", nil)
	r.Header.Set("Authorization", "Bearer "+forgedUnsignedJWT())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestSubjectRoundTrip(t *testing.T) {
	ctx := withSubject(context.Background(), "user-42")
	if got := Subject(ctx); got != "user-42" {
		t.Errorf("Subject roundtrip = %q, want user-42", got)
	}
	if got := Subject(context.Background()); got != "" {
		t.Errorf("Subject on empty ctx = %q, want empty", got)
	}
}

// startBogusProvider serves the minimum OIDC discovery + JWKS that go-oidc
// needs to construct a Provider. It does not actually sign anything; tokens
// fail verification with "invalid_token".
func startBogusProvider(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                "https://gateway.example",
			"authorization_endpoint":                "https://gateway.example/auth",
			"token_endpoint":                        "https://gateway.example/token",
			"jwks_uri":                              srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	return srv
}

func forgedUnsignedJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","aud":"mcp","iss":"https://gateway.example","exp":9999999999}`))
	return header + "." + payload + "."
}
