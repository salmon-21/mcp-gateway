// Package proxy implements the per-backend reverse proxy that fronts the
// authenticated MCP endpoints.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/salmon-21/mcp-gateway/internal/config"
)

// Backend wraps a single configured upstream as a ready-to-serve handler.
type Backend struct {
	Name    string
	Prefix  string
	proxy   *httputil.ReverseProxy
}

// New builds a Backend from a config entry. The returned handler strips the
// configured prefix from the request path before forwarding to upstream,
// passes through whitelisted headers, and (for SSE backends) flushes after
// every write so streamableHttp responses are not buffered.
func New(b config.Backend) (*Backend, error) {
	up, err := url.Parse(b.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream url %q: %w", b.Upstream, err)
	}
	if up.Scheme == "" || up.Host == "" {
		return nil, fmt.Errorf("upstream url %q lacks scheme/host", b.Upstream)
	}

	prefix := strings.TrimRight(b.Prefix, "/")
	headerAllowlist := append([]string{
		"Mcp-Session-Id",
		"Accept",
		"Content-Type",
	}, b.Headers...)

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(r.In.URL.Path, prefix)
			r.Out.URL.Scheme = up.Scheme
			r.Out.URL.Host = up.Host
			r.Out.URL.Path = singleJoiningSlash(up.Path, rest)
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			r.Out.Host = up.Host

			for _, h := range headerAllowlist {
				if v := r.In.Header.Values(h); len(v) > 0 {
					r.Out.Header[h] = v
				}
			}
			r.SetXForwarded()
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: b.Timeout,
			IdleConnTimeout:       90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("upstream error", "backend", b.Name, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	if b.SSE {
		rp.FlushInterval = -1
	}

	return &Backend{Name: b.Name, Prefix: prefix, proxy: rp}, nil
}

// ServeHTTP forwards the request to the configured upstream.
func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.proxy.ServeHTTP(w, r)
}

// Patterns are the path patterns to register on http.ServeMux. Both the
// exact prefix and the subtree variant are needed: registering only the
// subtree pattern (e.g. "/mcp/hc/") makes the mux 301-redirect the bare
// "/mcp/hc" to "/mcp/hc/", which discards the POST body on most clients.
// Registering both makes the exact path resolve to the handler directly.
func (b *Backend) Patterns() []string {
	return []string{b.Prefix, b.Prefix + "/"}
}

func singleJoiningSlash(a, b string) string {
	if a == "" {
		if !strings.HasPrefix(b, "/") {
			return "/" + b
		}
		return b
	}
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}
