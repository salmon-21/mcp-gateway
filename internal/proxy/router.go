// Package proxy implements the per-backend reverse proxy that fronts the
// authenticated MCP endpoints.
package proxy

import (
	"fmt"
	"log/slog"
	"net"
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
	// stripHeaders are the request headers httputil.ProxyRequest forwards by
	// default that we must not leak. Authorization carries the gateway's JWT,
	// which the backend has no business seeing — the gateway has already
	// validated it and the backend trusts the proxy entirely.
	stripHeaders := []string{"Authorization", "Cookie"}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(r.In.URL.Path, prefix)
			r.Out.URL.Path = rest
			r.Out.URL.RawPath = ""
			r.SetURL(up)
			for _, h := range stripHeaders {
				r.Out.Header.Del(h)
			}
			r.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: b.Timeout,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   10,
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

