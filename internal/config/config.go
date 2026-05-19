// Package config loads and validates the gateway's YAML configuration.
package config

import "time"

type Config struct {
	Listen             string        `yaml:"listen"`
	ReadHeaderTimeout  time.Duration `yaml:"read_header_timeout"`
	ShutdownTimeout    time.Duration `yaml:"shutdown_timeout"`
	ExternalURL        string        `yaml:"external_url"`
	Dex                Dex           `yaml:"dex"`
	JWT                JWT           `yaml:"jwt"`
	Backends           []Backend     `yaml:"backends"`
	Log                Log           `yaml:"log"`
}

type Dex struct {
	PublicURL        string `yaml:"public_url"`
	InternalURL      string `yaml:"internal_url"`
	GrpcURL          string `yaml:"grpc_url"`
	GrpcTLS          bool   `yaml:"grpc_tls"`
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
}

type JWT struct {
	Audience      []string      `yaml:"audience"`
	JwksCacheTTL  time.Duration `yaml:"jwks_cache_ttl"`
	ClockSkew     time.Duration `yaml:"clock_skew"`
}

type Backend struct {
	Name     string        `yaml:"name"`
	Prefix   string        `yaml:"prefix"`
	Upstream string        `yaml:"upstream"`
	Timeout  time.Duration `yaml:"timeout"`
	SSE      bool          `yaml:"sse"`
	Headers  []string      `yaml:"headers"`
}

type Log struct {
	Level              string `yaml:"level"`
	Format             string `yaml:"format"`
	IncludeRequestBody bool   `yaml:"include_request_body"`
}
