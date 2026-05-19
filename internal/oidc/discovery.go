package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ProtectedResource returns a handler serving the RFC 9728
// `oauth-protected-resource` metadata document. It is static given the
// gateway's external URL.
func ProtectedResource(externalURL string) http.Handler {
	body, _ := json.Marshal(map[string]any{
		"resource":                 externalURL,
		"authorization_servers":    []string{externalURL},
		"scopes_supported":         []string{"openid", "profile", "email", "offline_access"},
		"bearer_methods_supported": []string{"header"},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

// Discovery serves /.well-known/oauth-authorization-server and
// /.well-known/openid-configuration by fetching Dex's
// openid-configuration over the internal network, injecting
// `registration_endpoint` (which Dex itself does not advertise because it
// has no native DCR), and caching the result.
type Discovery struct {
	dexInternalURL string
	externalURL    string
	ttl            time.Duration
	client         *http.Client
	cache          atomic.Pointer[discoveryDoc]
}

type discoveryDoc struct {
	body []byte
	exp  time.Time
}

func NewDiscovery(dexInternalURL, externalURL string) *Discovery {
	return &Discovery{
		dexInternalURL: strings.TrimRight(dexInternalURL, "/"),
		externalURL:    externalURL,
		ttl:            5 * time.Minute,
		client:         &http.Client{Timeout: 5 * time.Second},
	}
}

func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc := d.cache.Load()
	if doc == nil || time.Now().After(doc.exp) {
		fresh, err := d.fetch(r.Context())
		if err != nil {
			if doc != nil {
				// stale-while-error: serve cached body if upstream is down.
				slog.Warn("discovery upstream failed, serving stale", "err", err)
			} else {
				slog.Error("discovery upstream failed, no cache", "err", err)
				http.Error(w, "discovery unavailable", http.StatusBadGateway)
				return
			}
		} else {
			d.cache.Store(fresh)
			doc = fresh
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(doc.body)
}

func (d *Discovery) fetch(ctx context.Context) (*discoveryDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		d.dexInternalURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("dex returned %d", resp.StatusCode)
	}
	// openid-configuration is well under 64 KiB in practice; the cap guards
	// against a runaway upstream serving garbage.
	body := io.LimitReader(resp.Body, 64<<10)
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	// Advertise OAuth endpoints under /oauth/* so MCP clients (notably
	// claude.ai) that hard-code that convention regardless of discovery
	// still find them. The gateway aliases these to Dex's /auth and /token
	// internally — see oidc.OAuthAliases.
	m["authorization_endpoint"] = d.externalURL + "/oauth/authorize"
	m["token_endpoint"] = d.externalURL + "/oauth/token"
	m["registration_endpoint"] = d.externalURL + "/oauth/register"
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &discoveryDoc{body: out, exp: time.Now().Add(d.ttl)}, nil
}
