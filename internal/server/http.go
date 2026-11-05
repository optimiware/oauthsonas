package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
)

const (
	htmlCSP        = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
	maxFormBytes   = 64 << 10
	corsAllowedHdr = "Authorization, Content-Type"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		s.logger.LogAttrs(r.Context(), slog.LevelInfo, "http",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", lrw.status),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

// logInfo records a successful or informational OAuth event.
func (s *Server) logInfo(r *http.Request, event, status string, attrs ...slog.Attr) {
	all := append([]slog.Attr{slog.String("status", status)}, attrs...)
	s.logger.LogAttrs(r.Context(), slog.LevelInfo, event, all...)
}

// logFail records a rejected request. Internal failures log at error level,
// everything else at warn.
func (s *Server) logFail(r *http.Request, event, category, message string, attrs ...slog.Attr) {
	level := slog.LevelWarn
	if category == "internal" {
		level = slog.LevelError
	}
	all := append([]slog.Attr{slog.String("status", "error"), slog.String("error_category", category)}, attrs...)
	all = append(all, slog.String("error", message))
	s.logger.LogAttrs(r.Context(), level, event, all...)
}

// parseForm parses a size-limited request form.
func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

// rejectRepeated reports the first of names that occurs more than once in values.
func rejectRepeated(values map[string][]string, names ...string) (string, bool) {
	for _, name := range names {
		if len(values[name]) > 1 {
			return name, true
		}
	}
	return "", false
}

// htmlHeaders sets the security headers shared by every HTML page.
func htmlHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", htmlCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Type", "text/html; charset=utf-8")
}

// renderHTML executes a named template into a buffer first so a template
// failure produces a clean 500 instead of a truncated page.
func renderHTML(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	htmlHeaders(w)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func setCORS(w http.ResponseWriter, origin string, methods []string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	h.Set("Access-Control-Allow-Headers", corsAllowedHdr)
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate")
}

func clearCORS(w http.ResponseWriter) {
	h := w.Header()
	for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers"} {
		h.Del(name)
	}
}

// originAllowedByAnyClient reports whether any registered client lists origin.
func (s *Server) originAllowedByAnyClient(origin string) bool {
	for _, client := range s.clients {
		if slices.Contains(client.AllowedOrigins, origin) {
			return true
		}
	}
	return false
}

// preflight answers CORS preflight requests for endpoints whose callers are not
// known yet: any origin registered by any client may ask.
func (s *Server) preflight(methods ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if origin == "" {
			methodNotAllowed(w, methods...)
			return
		}
		if !s.originAllowedByAnyClient(origin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		setCORS(w, origin, methods)
		w.WriteHeader(http.StatusNoContent)
	}
}

// unionCORS adds CORS headers to a public read endpoint (discovery, JWKS) when
// the origin belongs to any registered client. It never emits a wildcard.
func (s *Server) unionCORS(w http.ResponseWriter, r *http.Request, methods ...string) {
	w.Header().Set("Vary", "Origin")
	if origin := r.Header.Get("Origin"); origin != "" && s.originAllowedByAnyClient(origin) {
		setCORS(w, origin, methods)
	}
}

// clientCORS applies CORS for an endpoint serving a known client. It returns
// false after writing a 403 when the origin is not registered for that client.
func clientCORS(w http.ResponseWriter, r *http.Request, client config.Client, methods ...string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	w.Header().Set("Vary", "Origin")
	if !slices.Contains(client.AllowedOrigins, origin) {
		clearCORS(w)
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	setCORS(w, origin, methods)
	return true
}
