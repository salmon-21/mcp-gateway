package config

import (
	"strings"
	"testing"
)

func TestValidateAbsoluteHTTPURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr string // substring, empty = expect no error
	}{
		{"http internal", "http://dex:5556", ""},
		{"https external", "https://example.com", ""},
		{"missing scheme", "dex:5556", "must use http or https"},
		{"ftp scheme", "ftp://example.com", "must use http or https"},
		{"empty host", "https://", "missing host"},
		{"garbage", "::not-a-url", "parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateAbsoluteHTTPURL(c.url, "f")
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Errorf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestValidateRejectsBadBackend(t *testing.T) {
	base := func() *Config {
		return &Config{
			Listen:      ":9000",
			ExternalURL: "https://gw.example",
			Dex: Dex{
				PublicURL:   "https://gw.example",
				InternalURL: "http://dex:5556",
				GrpcURL:     "dex:5557",
			},
			Backends: []Backend{
				{Name: "ok", Prefix: "/mcp/ok", Upstream: "http://ok:1/mcp"},
			},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"prefix no slash", func(c *Config) { c.Backends[0].Prefix = "mcp/x" }, "must start with /"},
		{"prefix trailing slash", func(c *Config) { c.Backends[0].Prefix = "/mcp/x/" }, "must start with / and not end"},
		{"duplicate prefix", func(c *Config) {
			c.Backends = append(c.Backends, Backend{Name: "dup", Prefix: "/mcp/ok", Upstream: "http://b:1/mcp"})
		}, "duplicated"},
		{"bad upstream scheme", func(c *Config) { c.Backends[0].Upstream = "ftp://x" }, "http or https"},
		{"external_url not https", func(c *Config) { c.ExternalURL = "http://gw.example" }, "must use https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mutate(cfg)
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

func TestValidateAcceptsHappyPath(t *testing.T) {
	cfg := &Config{
		Listen:      ":9000",
		ExternalURL: "https://gw.example",
		Dex: Dex{
			PublicURL:   "https://gw.example",
			InternalURL: "http://dex:5556",
			GrpcURL:     "dex:5557",
		},
		Backends: []Backend{
			{Name: "toggl", Prefix: "/mcp/toggl", Upstream: "http://toggl:8099/mcp"},
		},
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("happy-path validate failed: %v", err)
	}
}
