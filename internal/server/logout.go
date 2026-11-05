package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v3"
)

// logout handles GET and POST /logout (RP-initiated logout). It holds no session, so
// it only validates and performs the post-logout redirect.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	q := r.Form
	target, clientID, idTokenHint := q.Get("post_logout_redirect_uri"), q.Get("client_id"), q.Get("id_token_hint")
	if idTokenHint != "" {
		hintClientID, err := s.clientIDFromIDTokenHint(idTokenHint)
		switch {
		case err != nil:
			s.logFail(r, "logout", "validation", "id_token_hint validation failed")
		case clientID == "":
			clientID = hintClientID
		case hintClientID != clientID:
			s.logger.LogAttrs(r.Context(), slog.LevelWarn, "logout",
				slog.String("status", "warning"),
				slog.String("client_id_param", clientID),
				slog.String("client_id_hint", hintClientID))
		}
	}
	if target == "" {
		s.logInfo(r, "logout", "plain", slog.String("client_id", clientID))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("logged out\n"))
		return
	}
	if !s.validPostLogoutURI(clientID, target) {
		s.logFail(r, "logout", "validation", "unregistered post_logout_redirect_uri", slog.String("client_id", clientID))
		http.Error(w, "unregistered post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	s.logInfo(r, "logout", "redirect", slog.String("client_id", clientID))
	if state := q.Get("state"); state != "" {
		query := redirect.Query()
		query.Set("state", state)
		redirect.RawQuery = query.Encode()
	}
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// clientIDFromIDTokenHint verifies hint against this server's signing key and
// returns the client it was issued to. Expiry is deliberately not checked:
// RP-initiated logout commonly presents an expired ID token.
func (s *Server) clientIDFromIDTokenHint(hint string) (string, error) {
	jws, err := jose.ParseSigned(hint)
	if err != nil {
		return "", fmt.Errorf("id_token_hint parse: %w", err)
	}
	payload, err := jws.Verify(s.key.Public())
	if err != nil {
		return "", fmt.Errorf("id_token_hint verify: %w", err)
	}
	var claims struct {
		ClientID string      `json:"client_id"`
		Audience interface{} `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("id_token_hint claims: %w", err)
	}
	switch aud := claims.Audience.(type) {
	case string:
		return aud, nil
	case []interface{}:
		if len(aud) > 0 {
			if first, ok := aud[0].(string); ok {
				return first, nil
			}
		}
	}
	if claims.ClientID != "" {
		return claims.ClientID, nil
	}
	return "", fmt.Errorf("id_token_hint: no client identifier found")
}

func (s *Server) validPostLogoutURI(clientID, target string) bool {
	if clientID != "" {
		client, ok := s.clients[clientID]
		return ok && slices.Contains(client.PostLogoutRedirectURIs, target)
	}
	for _, client := range s.clients {
		if slices.Contains(client.PostLogoutRedirectURIs, target) {
			return true
		}
	}
	return false
}
