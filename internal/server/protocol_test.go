package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func redirectError(t *testing.T, response *http.Response) (code, state string) {
	t.Helper()
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect", response.StatusCode)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(location.String(), "http://127.0.0.1:5173/auth/callback") {
		t.Fatalf("error redirected to %q", location)
	}
	return location.Query().Get("error"), location.Query().Get("state")
}

func TestPromptNoneReturnsLoginRequiredWithoutPicker(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	for name, hint := range map[string]string{"no hint": "", "with login_hint": "acme-admin"} {
		t.Run(name, func(t *testing.T) {
			params := validAuthorizeParams()
			params.Set("prompt", "none")
			if hint != "" {
				params.Set("login_hint", hint)
			}
			response, err := client.Get(authorizeURL(p.baseURL, params))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			code, state := redirectError(t, response)
			if code != "login_required" || state != "state-value-123" {
				t.Fatalf("error=%q state=%q, want login_required with state", code, state)
			}
		})
	}
}

func TestPromptValidation(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	for name, tc := range map[string]struct{ prompt, wantError string }{
		"unknown value":       {"bogus", "invalid_request"},
		"none with login":     {"none login", "invalid_request"},
		"login is a picker":   {"login", ""},
		"consent is a picker": {"consent select_account", ""},
	} {
		t.Run(name, func(t *testing.T) {
			params := validAuthorizeParams()
			params.Set("prompt", tc.prompt)
			response, err := client.Get(authorizeURL(p.baseURL, params))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if tc.wantError == "" {
				if response.StatusCode != http.StatusOK {
					t.Fatalf("prompt=%q status = %d, want the picker", tc.prompt, response.StatusCode)
				}
				return
			}
			if code, _ := redirectError(t, response); code != tc.wantError {
				t.Fatalf("prompt=%q error = %q, want %q", tc.prompt, code, tc.wantError)
			}
		})
	}
}

func TestLogoutAcceptsPost(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	response, err := client.PostForm(p.baseURL+"/logout", url.Values{
		"post_logout_redirect_uri": {"http://127.0.0.1:5173/"},
		"client_id":                {"dashboard"},
		"state":                    {"bye"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || !strings.Contains(response.Header.Get("Location"), "state=bye") {
		t.Fatalf("POST logout: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestUserinfoErrorsCarryCORSForRegisteredOrigins(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	for name, tc := range map[string]struct {
		origin    string
		wantAllow string
	}{
		"registered origin":   {"http://127.0.0.1:5173", "http://127.0.0.1:5173"},
		"unregistered origin": {"http://evil.example", ""},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, p.baseURL+"/userinfo", nil)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Authorization", "Bearer not-a-token")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.StatusCode)
			}
			if got := response.Header.Get("Access-Control-Allow-Origin"); got != tc.wantAllow {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantAllow)
			}
			if tc.wantAllow != "" && !strings.Contains(response.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
				t.Fatalf("WWW-Authenticate not exposed: %q", response.Header.Get("Access-Control-Expose-Headers"))
			}
		})
	}
}

func TestTokenEndpointCORS(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	post := func(origin, clientID string) *http.Response {
		t.Helper()
		request, _ := http.NewRequest(http.MethodPost, p.baseURL+"/oauth2/token",
			strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {"x"}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response
	}

	if r := post("http://127.0.0.1:5173", "dashboard"); r.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
		t.Errorf("registered origin: ACAO = %q", r.Header.Get("Access-Control-Allow-Origin"))
	}
	if r := post("http://evil.example", "dashboard"); r.StatusCode != http.StatusForbidden || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("unregistered origin: status=%d ACAO=%q", r.StatusCode, r.Header.Get("Access-Control-Allow-Origin"))
	}
	if r := post("http://127.0.0.1:5173", "unknown"); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("unknown client must not receive CORS headers, got %q", r.Header.Get("Access-Control-Allow-Origin"))
	}
	if r := post("", "dashboard"); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("no Origin must not produce CORS headers")
	}
}

func TestTokenEndpointIgnoresQueryParameters(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	code := selectPersona(t, p, client, begin(t, p, client, validAuthorizeParams()), "acme-admin")
	// A code_verifier supplied only in the query string must not be honored.
	response, err := client.PostForm(p.baseURL+"/oauth2/token?code_verifier="+verifier, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"dashboard"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:5173/auth/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("token endpoint accepted a code_verifier from the query string")
	}
}
