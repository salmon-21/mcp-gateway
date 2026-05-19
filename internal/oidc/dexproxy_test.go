package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDexProxyPreservesPath(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
	}))
	defer upstream.Close()

	h, err := NewDexProxy(upstream.URL, "")
	if err != nil {
		t.Fatalf("NewDexProxy: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/github?x=1", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if got != "/auth/github" {
		t.Errorf("upstream saw %q, want /auth/github (passthrough)", got)
	}
}

func TestDexProxyRewritesPath(t *testing.T) {
	var (
		gotPath  string
		gotQuery string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
	}))
	defer upstream.Close()

	h, err := NewDexProxy(upstream.URL, "/auth")
	if err != nil {
		t.Fatalf("NewDexProxy: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id=x&state=y", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if gotPath != "/auth" {
		t.Errorf("upstream path = %q, want /auth (rewrite)", gotPath)
	}
	values, _ := url.ParseQuery(gotQuery)
	if values.Get("client_id") != "x" || values.Get("state") != "y" {
		t.Errorf("query string lost: got %q", gotQuery)
	}
}

func TestDexProxyRejectsBadURL(t *testing.T) {
	if _, err := NewDexProxy("not-a-url", ""); err == nil {
		t.Fatal("expected error for malformed URL")
	}
	if _, err := NewDexProxy("", ""); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestOAuthAliasesAreNonEmpty(t *testing.T) {
	a := OAuthAliases()
	if len(a) == 0 {
		t.Fatal("OAuthAliases is empty")
	}
	for src, dst := range a {
		if !strings.HasPrefix(src, "/oauth/") {
			t.Errorf("alias %q must start with /oauth/", src)
		}
		if !strings.HasPrefix(dst, "/") {
			t.Errorf("target %q must start with /", dst)
		}
	}
}
