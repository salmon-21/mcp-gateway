package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/salmon-21/mcp-gateway/internal/config"
	"github.com/salmon-21/mcp-gateway/internal/oidc"
	"github.com/salmon-21/mcp-gateway/internal/proxy"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/mcp-gateway/config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, *cfgPath); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	initLogger(cfg.Log)
	slog.Info("starting", "version", version, "listen", cfg.Listen, "backends", len(cfg.Backends))

	verifier, err := oidc.NewVerifier(ctx, cfg.Dex.InternalURL, cfg.Dex.PublicURL, cfg.JWT.Audience, cfg.JWT.ClockSkew)
	if err != nil {
		return fmt.Errorf("oidc verifier: %w", err)
	}
	authMW := verifier.Middleware(cfg.ExternalURL)

	dexProxy, err := oidc.NewDexProxy(cfg.Dex.InternalURL)
	if err != nil {
		return fmt.Errorf("dex proxy: %w", err)
	}
	discovery := oidc.NewDiscovery(cfg.Dex.InternalURL, cfg.ExternalURL)
	protected := oidc.ProtectedResource(cfg.ExternalURL)
	dcr, err := oidc.NewDCR(cfg.Dex.GrpcURL)
	if err != nil {
		return fmt.Errorf("dcr: %w", err)
	}
	defer func() { _ = dcr.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/.well-known/oauth-protected-resource", protected)
	mux.Handle("/.well-known/oauth-authorization-server", discovery)
	mux.Handle("/.well-known/openid-configuration", discovery)
	mux.Handle("/oauth/register", dcr)
	for _, p := range oidc.DexProxyPaths() {
		mux.Handle(p, dexProxy)
	}
	for aliasPath, dexPath := range oidc.OAuthAliases() {
		ap, err := oidc.NewDexAliasProxy(cfg.Dex.InternalURL, dexPath)
		if err != nil {
			return fmt.Errorf("dex alias proxy %s→%s: %w", aliasPath, dexPath, err)
		}
		mux.Handle(aliasPath, ap)
	}
	for _, bc := range cfg.Backends {
		b, err := proxy.New(bc)
		if err != nil {
			return fmt.Errorf("backend %s: %w", bc.Name, err)
		}
		handler := authMW(b)
		for _, p := range b.Patterns() {
			mux.Handle(p, handler)
		}
		slog.Info("backend registered", "name", b.Name, "prefix", b.Prefix)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func initLogger(c config.Log) {
	level := slog.LevelInfo
	switch c.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if c.Format == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}
