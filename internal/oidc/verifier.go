// Package oidc contains the OIDC verifier, DCR handler, and discovery
// endpoints that the gateway exposes in front of Dex.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier wraps a go-oidc IDTokenVerifier and accepts any audience from a
// configured allow-list. JWTs minted by Dex after DCR carry the
// dynamically-registered client_id as aud, so we cannot check against a
// single constant; we let go-oidc verify signature/exp/iss and audit the
// audience ourselves.
type Verifier struct {
	verifier   *oidc.IDTokenVerifier
	allowedAud []string
}

// NewVerifier dials the Dex internal URL to fetch OIDC metadata and JWKS,
// then returns a Verifier that validates tokens issued by that Dex.
//
// Dex is typically reachable from the gateway at an internal hostname
// (e.g. http://dex:5556) but advertises a public issuer URL in its
// openid-configuration (e.g. https://example.com). go-oidc rejects that
// mismatch by default, so we tell it the issuer we expect using
// InsecureIssuerURLContext — the name is a misnomer; the only thing that
// becomes "insecure" is that the discovery URL no longer has to equal the
// issuer claim, which is the whole point of running Dex behind a reverse
// proxy.
//
// clockSkew is applied by shifting go-oidc's "now" backwards, which is the
// only knob the underlying library exposes for skew tolerance.
func NewVerifier(ctx context.Context, internalURL, expectedIssuer string, allowedAudience []string, clockSkew time.Duration) (*Verifier, error) {
	if expectedIssuer != "" && expectedIssuer != internalURL {
		ctx = oidc.InsecureIssuerURLContext(ctx, expectedIssuer)
	}
	provider, err := oidc.NewProvider(ctx, internalURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	cfg := &oidc.Config{
		SkipClientIDCheck: true,
		Now:               func() time.Time { return time.Now().Add(-clockSkew) },
	}
	return &Verifier{
		verifier:   provider.Verifier(cfg),
		allowedAud: allowedAudience,
	}, nil
}

// Verify parses and validates a raw JWT, returning the subject on success.
// Audience is checked only when an allow-list is configured.
func (v *Verifier) Verify(ctx context.Context, raw string) (sub string, err error) {
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	if len(v.allowedAud) > 0 && !v.audienceMatches(tok.Audience) {
		return "", fmt.Errorf("audience %v not in allow-list %v", tok.Audience, v.allowedAud)
	}
	return tok.Subject, nil
}

func (v *Verifier) audienceMatches(tokenAud []string) bool {
	for _, want := range v.allowedAud {
		if slices.Contains(tokenAud, want) {
			return true
		}
	}
	return false
}

// Middleware returns an http.Handler that validates the bearer token and
// injects the JWT subject into the request context. On failure it returns
// 401 with a WWW-Authenticate header pointing claude.ai at the
// protected-resource metadata endpoint, which triggers the OAuth re-auth
// flow per RFC 9728.
func (v *Verifier) Middleware(externalURL string) func(http.Handler) http.Handler {
	resourceMeta := externalURL + "/.well-known/oauth-protected-resource"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(r)
			if !ok {
				v.deny(w, resourceMeta, "missing bearer token")
				return
			}
			sub, err := v.Verify(r.Context(), raw)
			if err != nil {
				v.deny(w, resourceMeta, err.Error())
				return
			}
			ctx := withSubject(r.Context(), sub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (v *Verifier) deny(w http.ResponseWriter, resourceMeta, errDesc string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer resource_metadata="%s", error="invalid_token", error_description=%q`,
			resourceMeta, errDesc))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(p):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

type ctxKey struct{}

func withSubject(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, ctxKey{}, sub)
}

// Subject reads the JWT subject placed into the context by Middleware.
func Subject(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}
