// Package config loads and validates the gateway's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen            string        `yaml:"listen"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
	ExternalURL       string        `yaml:"external_url"`
	Dex               Dex           `yaml:"dex"`
	JWT               JWT           `yaml:"jwt"`
	Backends          []Backend     `yaml:"backends"`
	Log               Log           `yaml:"log"`
}

type Dex struct {
	PublicURL   string `yaml:"public_url"`
	InternalURL string `yaml:"internal_url"`
	GrpcURL     string `yaml:"grpc_url"`
}

type JWT struct {
	Audience  []string      `yaml:"audience"`
	ClockSkew time.Duration `yaml:"clock_skew"`
}

type Backend struct {
	Name     string        `yaml:"name"`
	Prefix   string        `yaml:"prefix"`
	Upstream string        `yaml:"upstream"`
	Timeout  time.Duration `yaml:"timeout"`
	SSE      bool          `yaml:"sse"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads, parses, applies defaults, and validates a YAML config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ReadHeaderTimeout == 0 {
		c.ReadHeaderTimeout = 10 * time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.JWT.ClockSkew == 0 {
		c.JWT.ClockSkew = 30 * time.Second
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	for i := range c.Backends {
		if c.Backends[i].Timeout == 0 {
			c.Backends[i].Timeout = 60 * time.Second
		}
	}
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if err := validateHTTPSURL(c.ExternalURL, "external_url"); err != nil {
		return err
	}
	if c.Dex.PublicURL == "" || c.Dex.InternalURL == "" || c.Dex.GrpcURL == "" {
		return errors.New("dex.{public_url,internal_url,grpc_url} are required")
	}
	if err := validateAbsoluteHTTPURL(c.Dex.InternalURL, "dex.internal_url"); err != nil {
		return err
	}
	if err := validateAbsoluteHTTPURL(c.Dex.PublicURL, "dex.public_url"); err != nil {
		return err
	}
	if len(c.Backends) == 0 {
		return errors.New("at least one backend is required")
	}
	seenPrefix := map[string]bool{}
	for i, b := range c.Backends {
		if b.Name == "" || b.Prefix == "" || b.Upstream == "" {
			return fmt.Errorf("backends[%d]: name/prefix/upstream required", i)
		}
		if !strings.HasPrefix(b.Prefix, "/") || strings.HasSuffix(b.Prefix, "/") {
			return fmt.Errorf("backends[%d].prefix must start with / and not end with /", i)
		}
		if seenPrefix[b.Prefix] {
			return fmt.Errorf("backends[%d].prefix duplicated: %s", i, b.Prefix)
		}
		seenPrefix[b.Prefix] = true
		if err := validateAbsoluteHTTPURL(b.Upstream, fmt.Sprintf("backends[%d].upstream", i)); err != nil {
			return err
		}
	}
	return nil
}

func validateAbsoluteHTTPURL(s, field string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must use http or https, got %q", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s missing host", field)
	}
	return nil
}

func validateHTTPSURL(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use https", field)
	}
	if strings.HasSuffix(s, "/") {
		return fmt.Errorf("%s must not end with /", field)
	}
	return nil
}
