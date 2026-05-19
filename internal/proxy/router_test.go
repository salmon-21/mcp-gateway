package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salmon-21/mcp-gateway/internal/config"
)

func TestBackendRewritesPathAndPassesHeaders(t *testing.T) {
	var (
		gotPath    string
		gotSession string
		gotAccept  string
		gotForward string
		gotAuth    string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSession = r.Header.Get("Mcp-Session-Id")
		gotAccept = r.Header.Get("Accept")
		gotForward = r.Header.Get("X-Forwarded-Host")
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	b, err := New(config.Backend{
		Name:     "toggl",
		Prefix:   "/mcp/toggl",
		Upstream: upstream.URL + "/mcp",
		Timeout:  5 * time.Second,
		SSE:      true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/toggl/some/sub?x=1", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer must-not-leak")
	req.Header.Set("Mcp-Session-Id", "session-123")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Host = "gateway.example"
	rr := httptest.NewRecorder()

	b.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if gotPath != "/mcp/some/sub" {
		t.Errorf("upstream path = %q, want /mcp/some/sub", gotPath)
	}
	if gotSession != "session-123" {
		t.Errorf("Mcp-Session-Id not passed through: got %q", gotSession)
	}
	if gotAccept == "" {
		t.Errorf("Accept header should pass through, got empty")
	}
	if gotForward != "gateway.example" {
		t.Errorf("X-Forwarded-Host = %q, want gateway.example", gotForward)
	}
	if gotAuth != "" {
		t.Errorf("Authorization must be stripped before reaching upstream, got %q", gotAuth)
	}
}

func TestBackendRejectsBadUpstream(t *testing.T) {
	if _, err := New(config.Backend{Name: "x", Prefix: "/x", Upstream: "no-scheme-host"}); err == nil {
		t.Fatal("expected error for upstream without scheme/host")
	}
}
