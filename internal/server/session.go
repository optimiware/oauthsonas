package server

import (
	"encoding/json"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// session carries the claims for both the JWT access token (JWTClaims) and the
// ID token (DefaultSession.Claims).
type session struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

func newSession() *session {
	return &session{DefaultSession: openid.NewDefaultSession(), JWTClaims: &jwt.JWTClaims{Extra: map[string]interface{}{}}, JWTHeader: &jwt.Headers{}}
}

func (s *session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	if s.JWTClaims.Extra == nil {
		s.JWTClaims.Extra = map[string]interface{}{}
	}
	return s.JWTClaims
}

func (s *session) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

func (s *session) Clone() fosite.Session {
	// JSON round-tripping preserves every exported claim required during refresh.
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	clone := newSession()
	if err := json.Unmarshal(b, clone); err != nil {
		panic(err)
	}
	if clone.DefaultSession == nil {
		clone.DefaultSession = openid.NewDefaultSession()
	}
	return clone
}

// personaSession builds the session for a persona. Application claims go into
// both tokens; email and name are ID-token/userinfo claims gated by scope.
func (s *Server) personaSession(p config.Persona, ar fosite.AuthorizeRequester) *session {
	sess := newSession()
	sess.Subject = p.Subject
	sess.Claims.Subject = p.Subject
	sess.Claims.AuthTime = time.Now().UTC()
	sess.Claims.Extra = map[string]interface{}{}
	sess.JWTClaims.Subject = p.Subject
	sess.JWTClaims.Extra["client_id"] = ar.GetClient().GetID()

	setBoth := func(name string, value interface{}) {
		sess.JWTClaims.Extra[name] = value
		sess.Claims.Extra[name] = value
	}
	setBoth(s.config.Claims.Roles, append([]string(nil), p.Roles...))
	if p.OrganizationID != "" {
		setBoth(s.config.Claims.OrgID, p.OrganizationID)
	}
	if len(p.Memberships) != 0 {
		setBoth(s.config.Claims.Memberships, append([]string(nil), p.Memberships...))
	}
	if ar.GetGrantedScopes().Has("email") {
		sess.Claims.Extra["email"] = p.Email
		sess.Claims.Extra["email_verified"] = true
	}
	if ar.GetGrantedScopes().Has("profile") {
		sess.Claims.Extra["name"] = p.Name
	}
	return sess
}

// removeScopeClaims drops scope-gated claims that a downscoped refresh no
// longer covers.
func removeScopeClaims(sess *session, scopes fosite.Arguments) {
	if !scopes.Has("email") {
		delete(sess.Claims.Extra, "email")
		delete(sess.Claims.Extra, "email_verified")
	}
	if !scopes.Has("profile") {
		delete(sess.Claims.Extra, "name")
	}
}
