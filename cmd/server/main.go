package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bitovi/temporal-codec/internal/auth"
	"github.com/bitovi/temporal-codec/internal/codec"
	"github.com/bitovi/temporal-codec/internal/config"
	"github.com/bitovi/temporal-codec/internal/httpapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "temporal-codec: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mgr, err := codec.New(ctx, codec.Options{
		DefaultURI:           cfg.EncryptionURI,
		NamespaceURIs:        cfg.NamespaceURIs,
		NamespaceURITemplate: cfg.NamespaceURITemplate,
	})
	if err != nil {
		return fmt.Errorf("codec: %w", err)
	}
	defer func() { _ = mgr.Close() }()

	var validator auth.Validator
	var authorizer auth.Authorizer
	ready := true

	if cfg.AuthDisabled {
		log.Warn("AUTH_DISABLED=true; namespace-bound authz is off — not for production")
		validator = auth.DisabledValidator{}
		authorizer = auth.AllowAllAuthorizer{}
	} else {
		v, err := auth.NewJWKSValidator(ctx, auth.JWKSConfig{
			URL:             cfg.JWKSURL,
			Audience:        cfg.JWTAudience,
			Issuer:          cfg.JWTIssuer,
			PermissionClaim: cfg.PermissionClaim,
			RefreshInterval: cfg.JWKSRefresh,
		})
		if err != nil {
			return fmt.Errorf("jwks: %w", err)
		}
		validator = v
		authorizer = auth.ClaimAuthorizer{}
	}

	srvAPI := httpapi.New(httpapi.Options{
		Logger:       log,
		Manager:      mgr,
		Validator:    validator,
		Authorizer:   authorizer,
		CORSOrigins:  cfg.CORSOrigins,
		Ready:        func() bool { return ready },
		EnableEncode: cfg.EnableEncode,
	})

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			"addr", httpServer.Addr,
			"auth_disabled", cfg.AuthDisabled,
			"enable_encode", cfg.EnableEncode,
			"cors_origins", strings.Join(cfg.CORSOrigins, ","),
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		ready = false
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
