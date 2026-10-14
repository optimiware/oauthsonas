package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestApplyEnvAccessCode(t *testing.T) {
	t.Setenv("OAUTHSONAS_ACCESS_CODE", "")
	c := accessCodeConfig("file-configured-code")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := ApplyEnv(c); err != nil {
		t.Fatalf("empty env override must disable the gate: %v", err)
	}
	if c.AccessCode != "" {
		t.Fatalf("env override not applied: %q", c.AccessCode)
	}
	t.Setenv("OAUTHSONAS_ACCESS_CODE", "environment-access-code")
	if err := ApplyEnv(c); err != nil {
		t.Fatalf("valid env override rejected: %v", err)
	}
	if c.AccessCode != "environment-access-code" {
		t.Fatalf("env override not applied: %q", c.AccessCode)
	}
	t.Setenv("OAUTHSONAS_ACCESS_CODE", "short")
	if err := ApplyEnv(c); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Fatalf("invalid env override accepted: %v", err)
	}
}
