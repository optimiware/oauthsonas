package server

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	gateCookie       = "oauthsonas_gate"
	gateSessionTTL   = 12 * time.Hour
	gateFailureDelay = 250 * time.Millisecond
)

// gateOpen reports whether the request may proceed past the optional access-code gate.
func (s *Server) gateOpen(r *http.Request) bool {
	if s.accessCode == "" {
		return true
	}
	cookie, err := r.Cookie(gateCookie)
	if err != nil {
		return false
	}
	_, ok := s.gate.get(cookie.Value)
	return ok
}

// renderGate renders the access-code form. returnTo is the original
// /oauth2/auth request URI that a successful submission bounces back to.
func (s *Server) renderGate(w http.ResponseWriter, returnTo string, status int, message string) {
	renderHTML(w, status, gateTemplate, gateData{ReturnTo: returnTo, Error: message})
}

// validGateReturnTo accepts only the local authorize request URI: a relative
// reference to /oauth2/auth with an optional query, never a scheme, host, or
// fragment.
func validGateReturnTo(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "//") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "/oauth2/auth"
}

// gateSubmit handles POST /oauth2/gate, the access-code form. On success it
// sets the gate cookie and redirects to the original authorize request; a
// wrong code re-renders the form with HTTP 401 after a fixed delay.
func (s *Server) gateSubmit(w http.ResponseWriter, r *http.Request) {
	if s.accessCode == "" {
		http.NotFound(w, r)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if name, repeated := rejectRepeated(r.PostForm, "code", "return_to"); repeated {
		http.Error(w, name+" must not be repeated", http.StatusBadRequest)
		return
	}
	returnTo := r.Form.Get("return_to")
	if !validGateReturnTo(returnTo) {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Form.Get("code")), []byte(s.accessCode)) != 1 {
		time.Sleep(gateFailureDelay)
		s.logFail(r, "gate", "auth", "invalid access code")
		s.renderGate(w, returnTo, http.StatusUnauthorized, "Invalid access code.")
		return
	}
	id, err := s.gate.put(struct{}{})
	if err != nil {
		s.logFail(r, "gate", "internal", err.Error())
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.cookie(gateCookie, id, "/", int(gateSessionTTL.Seconds())))
	s.logInfo(r, "gate", "success")
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}
