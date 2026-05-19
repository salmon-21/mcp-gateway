# mcp-gateway

Headless OAuth/DCR gateway for self-hosted MCP servers, fronting [Dex](https://dexidp.io/).

A small Go binary that sits in front of one or more MCP backends and:

- Serves OAuth 2.1 / OIDC discovery (`/.well-known/oauth-authorization-server`)
  and OAuth 2.0 protected-resource metadata (`/.well-known/oauth-protected-resource`,
  RFC 9728) so MCP clients like claude.ai can auto-discover authentication.
- Implements **Dynamic Client Registration** (RFC 7591) by forwarding to Dex's
  gRPC `CreateClient` API.
- Reverse-proxies the OAuth code/token flow to Dex; Dex federates upstream
  identity providers (GitHub etc.) and issues signed JWTs.
- Verifies the JWT on every `/mcp/{backend}/*` request (issuer, audience,
  expiry, signature against JWKS) and reverse-proxies authenticated traffic
  to the corresponding upstream MCP backend.

There is **no web UI** and **no database** in the gateway itself; configuration
is one YAML file, state lives in Dex.

## Status

Pre-1.0, single-user / self-host target. See [config.example.yaml](config.example.yaml).

## License

MIT — see [LICENSE](LICENSE).
