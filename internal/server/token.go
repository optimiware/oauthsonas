package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// token handles POST /oauth2/token for the authorization_code and
// refresh_token grants.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.logFail(r, "token", "validation", "bad form")
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if client, ok := s.clients[r.PostForm.Get("client_id")]; ok {
		// Unknown clients get no CORS headers; fosite returns the OAuth error.
		if !clientCORS(w, r, client, http.MethodPost) {
			return
		}
	}
	if name, repeated := rejectRepeated(r.PostForm, "grant_type", "client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "scope"); repeated {
		s.logFail(r, "token", "validation", name+" must not be repeated")
		s.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidRequest.WithHintf("%s must not be repeated", name))
		return
	}
	requestedScope, scopeProvided := r.PostForm["scope"]

	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	accessRequest, err := s.provider.NewAccessRequest(r.Context(), r, newSession())
	if err != nil {
		s.logFail(r, "token", "validation", err.Error(),
			slog.String("grant_type", r.PostForm.Get("grant_type")),
			slog.String("client_id", r.PostForm.Get("client_id")))
		s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
		return
	}
	clientID := accessRequest.GetClient().GetID()
	grantType := strings.Join(accessRequest.GetGrantTypes(), " ")

	if accessRequest.GetGrantTypes().Has("refresh_token") {
		if err := applyRefreshScope(accessRequest, requestedScope, scopeProvided); err != nil {
			s.logFail(r, "token", "validation", err.Error(),
				slog.String("grant_type", "refresh_token"), slog.String("client_id", clientID))
			s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
			return
		}
		if sess, ok := accessRequest.GetSession().(*session); ok {
			sess.JWTClaims.IssuedAt = time.Time{}
			sess.JWTClaims.JTI = ""
			removeScopeClaims(sess, accessRequest.GetGrantedScopes())
		}
	}
	response, err := s.provider.NewAccessResponse(r.Context(), accessRequest)
	if err != nil {
		s.logFail(r, "token", "internal", err.Error(),
			slog.String("grant_type", grantType), slog.String("client_id", clientID))
		s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
		return
	}
	s.logInfo(r, "token", "issued", slog.String("client_id", clientID), slog.String("grant_type", grantType))
	s.provider.WriteAccessResponse(r.Context(), w, accessRequest, response)
}

// applyRefreshScope lets a refresh request narrow, never widen, the granted scope.
func applyRefreshScope(request fosite.AccessRequester, values []string, provided bool) error {
	if !provided {
		return nil
	}
	scopes := fosite.Arguments(strings.Fields(values[0]))
	if len(scopes) == 0 {
		return fosite.ErrInvalidScope.WithHint("scope must not be empty")
	}
	for _, scope := range scopes {
		if !request.GetGrantedScopes().Has(scope) {
			return fosite.ErrInvalidScope.WithHint("refresh scope must be granted by the original authorization")
		}
	}
	refresh, ok := request.(*fosite.AccessRequest)
	if !ok {
		return fosite.ErrServerError.WithHint("unexpected refresh request type")
	}
	refresh.RequestedScope = scopes
	refresh.GrantedScope = scopes
	return nil
}
