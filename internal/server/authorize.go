package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/ory/fosite"
)

const (
	interactionCookie = "oauthsonas_interaction"
	interactionTTL    = 5 * time.Minute
)

// pendingAuthorize is a validated authorize request waiting for a persona choice.
type pendingAuthorize struct {
	request fosite.AuthorizeRequester
	csrf    string
}

// cookie builds a cookie with the attributes every oauthsonas cookie shares.
func (s *Server) cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Secure:   s.secureCookies,
	}
}

// authorize handles GET /oauth2/auth, the OIDC authorization endpoint.
//
// When an access_code is configured, a request without a valid oauthsonas_gate
// cookie receives the access-code form instead of completing (or rendering)
// anything; login_hint does not skip the gate.
//
// Optional login_hint=<persona id> (exactly one, ids only) completes the
// request in the same GET: the handler redirects to redirect_uri with code and
// state. No picker, cookie, or POST /oauth2/auth/select is required. A missing
// or unknown login_hint renders the HTML persona picker unchanged.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if !s.gateOpen(r) {
		s.renderGate(w, r.URL.RequestURI(), http.StatusOK, "")
		return
	}
	ar, err := s.provider.NewAuthorizeRequest(r.Context(), r)
	if err == nil {
		err = s.checkAuthorizeRequest(r, ar)
	}
	if err != nil {
		s.logFail(r, "authorize", "validation", err.Error(), slog.String("client_id", r.URL.Query().Get("client_id")))
		s.provider.WriteAuthorizeError(r.Context(), w, ar, err)
		return
	}
	clientID := ar.GetClient().GetID()

	hint := r.URL.Query().Get("login_hint")
	if persona, ok := s.personas[hint]; ok {
		s.logInfo(r, "authorize", "auto", slog.String("client_id", clientID), slog.String("persona_id", persona.ID))
		s.completeAuthorization(w, r, ar, persona)
		return
	}

	csrf, err := randomString(32)
	var id string
	if err == nil {
		id, err = s.interactions.put(pendingAuthorize{request: ar, csrf: csrf})
	}
	if err != nil {
		s.logFail(r, "authorize", "internal", err.Error(), slog.String("client_id", clientID))
		http.Error(w, "could not create interaction", http.StatusInternalServerError)
		return
	}
	attrs := []slog.Attr{slog.String("client_id", clientID), slog.String("interaction_id", id[:8])}
	if hint != "" {
		attrs = append(attrs, slog.Bool("hint_ignored", true))
	}
	s.logInfo(r, "authorize", "prompt", attrs...)

	http.SetCookie(w, s.cookie(interactionCookie+"_"+id, id, "/oauth2", int(interactionTTL.Seconds())))
	renderHTML(w, http.StatusOK, pickerTemplate, pickerData{Personas: s.personaList, CSRF: csrf, InteractionID: id})
}

// checkAuthorizeRequest applies the stricter-than-fosite rules this server
// enforces on browser authorize requests.
func (s *Server) checkAuthorizeRequest(r *http.Request, ar fosite.AuthorizeRequester) error {
	q := r.URL.Query()
	if name, repeated := rejectRepeated(q, "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "audience", "response_mode", "login_hint"); repeated {
		return fosite.ErrInvalidRequest.WithHintf("%s must not be repeated", name)
	}
	if q.Get("redirect_uri") == "" {
		return fosite.ErrInvalidRequest.WithHint("redirect_uri is required")
	}
	if q.Get("response_type") != "code" {
		return fosite.ErrInvalidRequest.WithHint("only response_type=code is supported")
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		return fosite.ErrInvalidRequest.WithHint("PKCE S256 code_challenge is required")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(challenge) != 43 || len(decoded) != 32 {
		return fosite.ErrInvalidRequest.WithHint("code_challenge must be a SHA-256 base64url value")
	}
	if client, ok := s.clients[q.Get("client_id")]; ok && !slices.Contains(client.RedirectURIs, q.Get("redirect_uri")) {
		return fosite.ErrInvalidRequest.WithHint("redirect_uri must exactly match a registered redirect_uri")
	}
	if nonce := q.Get("nonce"); nonce != "" && len(nonce) < fosite.MinParameterEntropy {
		return fosite.ErrInvalidRequest.WithHint("nonce must have sufficient entropy")
	}
	if audiences, present := q["audience"]; present && (len(audiences) != 1 || audiences[0] != s.config.APIAudience) {
		return fosite.ErrInvalidRequest.WithHint("audience must exactly equal the configured api_audience")
	}
	if !ar.GetRequestedScopes().Has("openid") {
		return fosite.ErrInvalidScope.WithHint("openid scope is required")
	}
	return nil
}

// selectPersona handles POST /oauth2/auth/select, the form submission that
// completes persona selection. The form fields (csrf, interaction_id, persona),
// the required oauthsonas_interaction_<id> cookie, and the test selectors are
// documented in the README under "Browser automation". Agents that cannot POST
// the form can use login_hint on GET /oauth2/auth instead.
func (s *Server) selectPersona(w http.ResponseWriter, r *http.Request) {
	if !s.gateOpen(r) {
		http.Error(w, "access code required", http.StatusForbidden)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if name, repeated := rejectRepeated(r.PostForm, "csrf", "interaction_id", "persona"); repeated {
		s.logFail(r, "select_persona", "validation", name+" must not be repeated")
		http.Error(w, name+" must not be repeated", http.StatusBadRequest)
		return
	}
	interactionID := r.Form.Get("interaction_id")
	if !validInteractionID(interactionID) {
		s.logFail(r, "select_persona", "validation", "invalid interaction")
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	cookie, err := r.Cookie(interactionCookie + "_" + interactionID)
	if err != nil || cookie.Value != interactionID {
		s.logFail(r, "select_persona", "auth", "invalid interaction cookie")
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	persona, ok := s.personas[r.Form.Get("persona")]
	if !ok {
		s.logFail(r, "select_persona", "validation", "unknown persona", slog.String("persona_id", r.Form.Get("persona")))
		http.Error(w, "unknown persona", http.StatusBadRequest)
		return
	}
	csrf := r.Form.Get("csrf")
	pending, ok := s.interactions.take(interactionID, func(p pendingAuthorize) bool {
		return subtle.ConstantTimeCompare([]byte(p.csrf), []byte(csrf)) == 1
	})
	if !ok {
		s.logFail(r, "select_persona", "auth", "invalid csrf or expired interaction",
			slog.String("persona_id", persona.ID), slog.String("interaction_id", interactionID[:8]))
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	s.logInfo(r, "select_persona", "success",
		slog.String("client_id", pending.request.GetClient().GetID()),
		slog.String("persona_id", persona.ID),
		slog.String("interaction_id", interactionID[:8]))
	http.SetCookie(w, s.cookie(interactionCookie+"_"+interactionID, "", "/oauth2", -1))
	s.completeAuthorization(w, r, pending.request, persona)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, persona config.Persona) {
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(s.config.APIAudience)
	sess := s.personaSession(persona, ar)

	s.storeMu.Lock()
	resp, err := s.provider.NewAuthorizeResponse(r.Context(), ar, sess)
	s.storeMu.Unlock()
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, ar, err)
		return
	}
	s.provider.WriteAuthorizeResponse(r.Context(), w, ar, resp)
}

func validInteractionID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
