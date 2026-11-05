package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

// userinfo handles GET and POST /userinfo for bearer access tokens.
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	token, err := bearerToken(w, r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(w, "invalid bearer token transport", http.StatusBadRequest)
		return
	}
	s.storeMu.Lock()
	_, accessRequest, err := s.provider.IntrospectToken(r.Context(), token, fosite.AccessToken, newSession())
	s.storeMu.Unlock()
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if !clientCORS(w, r, s.clients[accessRequest.GetClient().GetID()], http.MethodGet, http.MethodPost) {
		return
	}
	sess, ok := accessRequest.GetSession().(*session)
	if !ok {
		http.Error(w, "invalid session", http.StatusInternalServerError)
		return
	}
	granted := accessRequest.GetGrantedScopes()
	claims := sess.Claims.Extra

	result := map[string]interface{}{"sub": sess.GetSubject()}
	keys := []string{s.config.Claims.Roles, s.config.Claims.OrgID, s.config.Claims.Memberships}
	if granted.Has("email") {
		keys = append(keys, "email", "email_verified")
	}
	if granted.Has("profile") {
		keys = append(keys, "name")
	}
	for _, key := range keys {
		if value, ok := claims[key]; ok {
			result[key] = value
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

// bearerToken extracts the access token from exactly one Authorization header;
// query and form transport are rejected.
func bearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.URL.Query().Has("access_token") {
		return "", fmt.Errorf("query access tokens are not supported")
	}
	if err := parseForm(w, r); err != nil {
		return "", err
	}
	if _, ok := r.PostForm["access_token"]; ok {
		return "", fmt.Errorf("form access tokens are not supported")
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", fmt.Errorf("exactly one bearer authorization header is required")
	}
	token := strings.TrimSpace(strings.TrimPrefix(values[0], "Bearer "))
	if token == "" {
		return "", fmt.Errorf("exactly one bearer authorization header is required")
	}
	return token, nil
}
