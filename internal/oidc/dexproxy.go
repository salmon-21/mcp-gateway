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
// point is that these run before the user has a token.
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

// OAuthAliases maps the /oauth/* paths advertised in the gateway's discovery
// document to the actual Dex paths. Some MCP clients (notably claude.ai)
// hard-code /oauth/authorize and /oauth/token regardless of what the
// authorization-server metadata says, so the gateway accepts both shapes.
func OAuthAliases() map[string]string {
	return map[string]string{
		"/oauth/authorize": "/auth",
		"/oauth/token":     "/token",
	}
}

// NewDexProxy returns a reverse proxy targeting the Dex internal URL.
//
// When dexPath is empty the request path is preserved verbatim, which is
// what the transparent passthrough routes need (Dex's openid-configuration
// already advertises endpoints rooted at the gateway's external URL).
// When dexPath is non-empty the incoming path is replaced before forwarding
// — used by the /oauth/* alias routes that need to land on Dex's /auth and
// /token.
func NewDexProxy(internalURL, dexPath string) (http.Handler, error) {
	u, err := url.Parse(internalURL)
	if err != nil {
		return nil, fmt.Errorf("parse dex internal url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("dex internal url lacks scheme/host: %q", internalURL)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = u.Scheme
			r.Out.URL.Host = u.Host
			if dexPath != "" {
				r.Out.URL.Path = dexPath
				r.Out.URL.RawPath = ""
			}
			r.Out.Host = u.Host
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("dex upstream error", "path", r.URL.Path, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}, nil
}
