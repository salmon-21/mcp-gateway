// Package proxy implements the per-backend reverse proxy that fronts the
// authenticated MCP endpoints.
package proxy

// TODO: build an httputil.ReverseProxy per backend with prefix stripping,
// Mcp-Session-Id passthrough, and SSE-friendly flushing.
