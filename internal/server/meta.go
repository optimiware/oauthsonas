package server

import (
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
)

var supportedScopes = []string{"openid", "profile", "email", "offline_access"}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": s.version,
		"issuer":  s.config.Issuer,
		"uptime":  time.Since(s.startTime).String(),
	})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ready",
		"issuer": s.config.Issuer,
	})
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	s.unionCORS(w, r, http.MethodGet)
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, s.discoveryDoc)
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	s.unionCORS(w, r, http.MethodGet)
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{s.key.Public()}})
}

func discoveryDocument(issuer string, claimNames []string) map[string]interface{} {
	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/auth",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"end_session_endpoint":                  issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      supportedScopes,
		"code_challenge_methods_supported":      []string{"S256"},
		"subject_types_supported":               []string{"public"},
		"claims_supported":                      append([]string{"sub", "email", "email_verified", "name"}, claimNames...),
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"response_modes_supported":              []string{"query"},
		"request_uri_parameter_supported":       false,
	}
}
