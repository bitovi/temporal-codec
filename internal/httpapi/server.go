package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.temporal.io/sdk/converter"

	"github.com/bitovi/temporal-codec/internal/auth"
	"github.com/bitovi/temporal-codec/internal/codec"
)

// ReadyChecker returns true when the process is ready to serve traffic.
type ReadyChecker func() bool

// Server is the HTTP surface for temporal-codec.
type Server struct {
	log          *slog.Logger
	manager      *codec.Manager
	validator    auth.Validator
	authorizer   auth.Authorizer
	corsOrigins  map[string]struct{}
	ready        ReadyChecker
	enableEncode bool
	started      time.Time
}

// Options wires HTTP dependencies.
type Options struct {
	Logger       *slog.Logger
	Manager      *codec.Manager
	Validator    auth.Validator
	Authorizer   auth.Authorizer
	CORSOrigins  []string
	Ready        ReadyChecker
	// EnableEncode exposes POST /encode (local/debug only). Production is
	// decode-only: Temporal Cloud UI only calls /decode.
	EnableEncode bool
}

// New constructs Server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	origins := make(map[string]struct{}, len(opts.CORSOrigins))
	for _, o := range opts.CORSOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			origins[o] = struct{}{}
		}
	}
	return &Server{
		log:          opts.Logger,
		manager:      opts.Manager,
		validator:    opts.Validator,
		authorizer:   opts.Authorizer,
		corsOrigins:  origins,
		ready:        opts.Ready,
		enableEncode: opts.EnableEncode,
		started:      time.Now().UTC(),
	}
}

// Handler returns the root mux with CORS, auth, and routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)

	authMW := auth.Middleware(s.validator, s.authorizer)
	// Access log after auth so principal subject is available without logging tokens.
	mux.Handle("POST /decode", authMW(s.withAccessLog(http.HandlerFunc(s.handleCodec))))
	if s.enableEncode {
		mux.Handle("POST /encode", authMW(s.withAccessLog(http.HandlerFunc(s.handleCodec))))
	}

	return s.withCORS(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.ready() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "not_ready",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"started": s.started.Format(time.RFC3339),
	})
}

func (s *Server) handleCodec(w http.ResponseWriter, r *http.Request) {
	// X-Namespace was already JWT-bound by auth middleware. PayloadCodec
	// resolves only that namespace's CMK (never a foreign key or bare wire id).
	ns := strings.TrimSpace(r.Header.Get("X-Namespace"))
	pc := s.manager.PayloadCodec(ns)
	// Temporal payload codec HTTP shape (POST body: {"payloads":[...]}).
	converter.NewPayloadCodecHTTPHandler(pc).ServeHTTP(w, r)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)

		// Token sink: never log Authorization header, tokens, or bodies.
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.code,
			"duration_ms", time.Since(start).Milliseconds(),
		}
		if ns := r.Header.Get("X-Namespace"); ns != "" {
			attrs = append(attrs, "namespace", ns)
		}
		if p, ok := auth.PrincipalFrom(r.Context()); ok && p.Subject != "" {
			attrs = append(attrs, "principal", p.Subject)
		}
		s.log.Info("request", attrs...)
	})
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := s.corsOrigins[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Namespace")
				w.Header().Set("Access-Control-Max-Age", "3600")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
