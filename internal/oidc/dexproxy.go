package oidc

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// DexProxyPaths are the Dex HTTP paths the gateway transparently
// reverse-proxies so the entire OAuth/OIDC flow is served from the
// gateway's external URL. They are NOT behind JWT verification — the whole
// point is that these run *before* the user has a token.
//
// Patterns ending in "/" match the path and any subpath under it
// (Go ServeMux semantics).
func DexProxyPaths() []string {
	return []string{
		"/auth",
		"/auth/",
		"/token",
		"/keys",
		"/userinfo",
		"/callback",
		"/callback/",
		"/approval",
		"/static/",
		"/theme/",
	}
}

// NewDexProxy builds a reverse proxy targeting the Dex internal URL. The
// upstream path is preserved verbatim because Dex's issuer is configured to
// match the gateway's external URL, so endpoints advertised in
// openid-configuration line up 1:1.
func NewDexProxy(internalURL string) (http.Handler, error) {
	u, err := url.Parse(internalURL)
	if err != nil {
		return nil, fmt.Errorf("parse dex internal url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("dex internal url lacks scheme/host: %q", internalURL)
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = u.Scheme
			r.Out.URL.Host = u.Host
			r.Out.Host = u.Host
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("dex upstream error", "path", r.URL.Path, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return rp, nil
}

// OAuthAliases is the mapping from /oauth/* paths advertised in our
// discovery document to the actual Dex paths. Some MCP clients (claude.ai)
// hard-code /oauth/authorize and /oauth/token regardless of what the
// authorization-server metadata says, so we accept both shapes.
func OAuthAliases() map[string]string {
	return map[string]string{
		"/oauth/authorize": "/auth",
		"/oauth/token":     "/token",
	}
}

// NewDexAliasProxy is the same as NewDexProxy but rewrites the incoming
// alias path (`/oauth/authorize`) to the matching Dex path (`/auth`) before
// forwarding. One handler per alias.
func NewDexAliasProxy(internalURL, dexPath string) (http.Handler, error) {
	u, err := url.Parse(internalURL)
	if err != nil {
		return nil, fmt.Errorf("parse dex internal url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("dex internal url lacks scheme/host: %q", internalURL)
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = u.Scheme
			r.Out.URL.Host = u.Host
			r.Out.URL.Path = dexPath
			r.Out.URL.RawPath = ""
			r.Out.Host = u.Host
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("dex alias upstream error", "path", r.URL.Path, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return rp, nil
}
