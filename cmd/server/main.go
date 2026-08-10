package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
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
	var ready atomic.Bool
	ready.Store(true)

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

		claimAuth := auth.ClaimAuthorizer{}
		switch {
		case cfg.NamespaceACLFile != "":
			path := cfg.NamespaceACLFile
			authorizer = auth.EmailAuthorizer{
				LoadACL:  func() map[string][]string { return config.LoadNamespaceACLFile(path) },
				Fallback: claimAuth,
			}
			log.Info("authorization: EmailAuthorizer with NAMESPACE_ACL_FILE (reload-on-read)", "path", path)
		case len(cfg.NamespaceACL) > 0:
			authorizer = auth.EmailAuthorizer{
				ACL:      cfg.NamespaceACL,
				Fallback: claimAuth,
			}
			log.Info("authorization: EmailAuthorizer with NAMESPACE_ACL env", "emails", len(cfg.NamespaceACL))
		default:
			authorizer = claimAuth
			log.Info("authorization: ClaimAuthorizer only (no NAMESPACE_ACL / NAMESPACE_ACL_FILE)")
		}
	}

	srvAPI := httpapi.New(httpapi.Options{
		Logger:       log,
		Manager:      mgr,
		Validator:    validator,
		Authorizer:   authorizer,
		CORSOrigins:  cfg.CORSOrigins,
		Ready:        ready.Load,
		EnableEncode: cfg.EnableEncode,
		MaxBodyBytes: cfg.MaxBodyBytes,
	})

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
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
		// Mark unready before shutting down so the load balancer drains traffic
		// during the next health-check probe interval before we stop accepting.
		ready.Store(false)
		time.Sleep(5 * time.Second)
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
