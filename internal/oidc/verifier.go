// Package oidc contains the OIDC verifier, DCR handler, and discovery
// endpoints that the gateway exposes in front of Dex.
package oidc

// TODO: wrap go-oidc Provider/IDTokenVerifier; expose middleware that
// validates Authorization: Bearer <JWT> against Dex JWKS.
