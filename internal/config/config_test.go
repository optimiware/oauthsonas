package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `issuer: http://127.0.0.1:8181
api_audience: https://api.example.test
clients:
  - id: dashboard
    name: Dashboard
    public: true
    redirect_uris: [http://127.0.0.1:5173/callback]
    typo_origin: http://127.0.0.1:5173
personas:
  - id: user
    subject: oauthsonas|user
    email: user@example.test
    name: User
    roles: [viewer]
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "typo_origin") {
		t.Fatalf("unknown field accepted: %v", err)
	}
}

func TestValidateRejectsDuplicateIDsAndInvalidIssuer(t *testing.T) {
	c := &Config{
		Issuer: "not-a-url", APIAudience: "https://api.example.test",
		Clients:  []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas: []Persona{{ID: "one", Subject: "subject", Email: "one@example.test", Name: "One", Roles: []string{"viewer"}}, {ID: "one", Subject: "subject-two", Email: "two@example.test", Name: "Two", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("invalid issuer accepted: %v", err)
	}
	c.Issuer = "http://127.0.0.1:8181"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate persona id") {
		t.Fatalf("duplicate persona accepted: %v", err)
	}
}

func TestLoadRejectsAdditionalYAMLDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `issuer: http://127.0.0.1:8181
api_audience: https://api.example.test
clients:
  - id: dashboard
    name: Dashboard
    public: true
    redirect_uris: [http://127.0.0.1:5173/callback]
personas:
  - id: user
    subject: oauthsonas|user
    email: user@example.test
    name: User
    roles: [viewer]
---
ignored: document
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("additional YAML document accepted: %v", err)
	}
}

func TestValidateRequiresPersonasAndRootIssuer(t *testing.T) {
	c := &Config{
		Issuer:      "http://127.0.0.1:8181/tenant",
		APIAudience: "https://api.example.test",
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "issuer must not include a path") {
		t.Fatalf("issuer path accepted: %v", err)
	}
	c.Issuer = "http://127.0.0.1:8181"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at least one persona") {
		t.Fatalf("empty persona set accepted: %v", err)
	}
}

func TestValidateAllowsFixedRedirectQuery(t *testing.T) {
	c := &Config{
		Issuer:      "http://127.0.0.1:8181",
		APIAudience: "https://api.example.test",
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback?source=local"}}},
		Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("fixed redirect query rejected: %v", err)
	}
}

func TestValidateAppliesDefaultClaimNames(t *testing.T) {
	c := &Config{
		Issuer:      "http://127.0.0.1:8181",
		APIAudience: "https://api.example.test",
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Claims.Roles != "roles" || c.Claims.Memberships != "memberships" || c.Claims.OrgID != "org_id" {
		t.Fatalf("unexpected claim defaults: %#v", c.Claims)
	}
}

func TestValidateRejectsDuplicateClaimNames(t *testing.T) {
	c := &Config{
		Issuer:      "http://127.0.0.1:8181",
		APIAudience: "https://api.example.test",
		Claims:      Claims{Roles: "roles", Memberships: "roles", OrgID: "org_id"},
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "distinct claim names") {
		t.Fatalf("duplicate claim names accepted: %v", err)
	}
}

func TestValidateAllowsCustomClaimNames(t *testing.T) {
	c := &Config{
		Issuer:      "http://127.0.0.1:8181",
		APIAudience: "https://api.example.test",
		Claims:      Claims{Roles: "https://example.test/roles", Memberships: "https://example.test/memberships", OrgID: "organization_id"},
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("custom claim names rejected: %v", err)
	}
}

func TestValidateRejectsReservedClaimNames(t *testing.T) {
	reserved := []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "client_id", "scope", "kid"}
	for _, name := range reserved {
		t.Run(name, func(t *testing.T) {
			c := &Config{
				Issuer:      "http://127.0.0.1:8181",
				APIAudience: "https://api.example.test",
				Claims:      Claims{Roles: name, Memberships: "memberships", OrgID: "org_id"},
				Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
				Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
			}
			if err := c.Validate(); err == nil {
				t.Fatalf("reserved claim %q accepted", name)
			}
		})
	}
}

func accessCodeConfig(code string) *Config {
	return &Config{
		Issuer:      "http://127.0.0.1:8181",
		APIAudience: "https://api.example.test",
		AccessCode:  code,
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas:    []Persona{{ID: "user", Subject: "oauthsonas|user", Email: "user@example.test", Name: "User", Roles: []string{"viewer"}}},
	}
}

func TestValidateAccessCode(t *testing.T) {
	for name, tc := range map[string]struct {
		code    string
		wantErr string
	}{
		"empty disables the gate": {"", ""},
		"valid":                   {"correct-horse-battery", ""},
		"trimmed":                 {"  correct-horse-battery  ", ""},
		"too short":               {"short", "at least 16"},
		"whitespace":              {"correct horse battery", "whitespace"},
	} {
		t.Run(name, func(t *testing.T) {
			err := accessCodeConfig(tc.code).Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("access code %q rejected: %v", tc.code, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("access code %q: want error containing %q, got %v", tc.code, tc.wantErr, err)
			}
		})
	}
}

const minimalYAML = `issuer: http://127.0.0.1:8181
api_audience: https://api.example.test
%s
clients:
  - id: dashboard
    name: Dashboard
    public: true
    redirect_uris: [http://127.0.0.1:5173/callback]
personas:
  - id: user
    subject: oauthsonas|user
    email: user@example.test
    name: User
    roles: [viewer]
`

func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(minimalYAML, "%s", extra, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAccessCodeEnvOverride(t *testing.T) {
	path := writeConfig(t, "access_code: file-configured-code")

	t.Setenv("OAUTHSONAS_ACCESS_CODE", "")
	c, err := Load(path)
	if err != nil || c.AccessCode != "" {
		t.Fatalf("empty env override must disable the gate: code=%q err=%v", c.AccessCode, err)
	}

	t.Setenv("OAUTHSONAS_ACCESS_CODE", "environment-access-code")
	c, err = Load(path)
	if err != nil || c.AccessCode != "environment-access-code" {
		t.Fatalf("env override not applied: code=%q err=%v", c.AccessCode, err)
	}

	t.Setenv("OAUTHSONAS_ACCESS_CODE", "short")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Fatalf("invalid env override accepted: %v", err)
	}
}

func TestLoadDurations(t *testing.T) {
	t.Setenv("OAUTHSONAS_ACCESS_CODE", "")
	c, err := Load(writeConfig(t, "token_ttl: 30m\nrefresh_token_ttl: 24h"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TokenTTL.D() != 30*time.Minute || c.RefreshTokenTTL.D() != 24*time.Hour {
		t.Fatalf("durations = %v, %v", c.TokenTTL.D(), c.RefreshTokenTTL.D())
	}
	if c.AuthorizationCodeTTL.D() != 5*time.Minute {
		t.Fatalf("authorization_code_ttl default = %v", c.AuthorizationCodeTTL.D())
	}
	for _, bad := range []string{"token_ttl: 900", "token_ttl: soon", "token_ttl: -5m", "token_ttl: 0s"} {
		if _, err := Load(writeConfig(t, bad)); err == nil || !strings.Contains(err.Error(), "positive Go duration") {
			t.Errorf("%q: want duration error, got %v", bad, err)
		}
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	c := &Config{
		Issuer:      "not-a-url",
		APIAudience: "",
		AccessCode:  "short",
		Clients:     []Client{{ID: "dashboard", Name: "Dashboard", Public: false}},
		Personas:    []Persona{{ID: "one"}},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	for _, want := range []string{"issuer", "api_audience is required", "at least 16", "must set public", "at least one redirect_uri", "persona 0 requires"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestValidateOrigins(t *testing.T) {
	c := accessCodeConfig("")
	c.Clients[0].AllowedOrigins = []string{"http://127.0.0.1:5173/path"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "scheme and host only") {
		t.Fatalf("origin with a path accepted: %v", err)
	}
	c.Clients[0].AllowedOrigins = []string{"http://127.0.0.1:5173"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid origin rejected: %v", err)
	}
}

func TestLoadEmptyDurationUsesDefault(t *testing.T) {
	t.Setenv("OAUTHSONAS_ACCESS_CODE", "")
	for _, extra := range []string{`token_ttl: ""`, "token_ttl:", "token_ttl: null"} {
		c, err := Load(writeConfig(t, extra))
		if err != nil {
			t.Errorf("%q: %v", extra, err)
			continue
		}
		if c.TokenTTL.D() != 15*time.Minute {
			t.Errorf("%q: token_ttl = %v, want the 15m default", extra, c.TokenTTL.D())
		}
	}
}
