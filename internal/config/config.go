// Package config loads and validates the oauthsonas YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultTokenTTL             = 15 * time.Minute
	defaultAuthorizationCodeTTL = 5 * time.Minute
	defaultRefreshTokenTTL      = 8 * time.Hour
	minAccessCodeLength         = 16
)

// Config is the complete development OIDC server configuration.
type Config struct {
	Issuer               string    `yaml:"issuer"`
	APIAudience          string    `yaml:"api_audience"`
	AccessCode           string    `yaml:"access_code"`
	TokenTTL             Duration  `yaml:"token_ttl"`
	AuthorizationCodeTTL Duration  `yaml:"authorization_code_ttl"`
	RefreshTokenTTL      Duration  `yaml:"refresh_token_ttl"`
	AllowedRoles         []string  `yaml:"allowed_roles"`
	Claims               Claims    `yaml:"claims"`
	Clients              []Client  `yaml:"clients"`
	Personas             []Persona `yaml:"personas"`
}

// Duration is a positive time span written as a Go duration string such as
// "15m". An empty value keeps the default; bare numbers are rejected rather
// than read as nanoseconds.
type Duration time.Duration

// D returns the duration as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw == "" {
		return nil // unset or empty: keep the default
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fmt.Errorf("line %d: %q is not a positive Go duration such as 15m", node.Line, raw)
	}
	*d = Duration(parsed)
	return nil
}

// Claims configures JWT/userinfo claim names for application attributes.
type Claims struct {
	Roles       string `yaml:"roles"`
	Memberships string `yaml:"memberships"`
	OrgID       string `yaml:"org_id"`
}

type Client struct {
	ID                     string   `yaml:"id"`
	Name                   string   `yaml:"name"`
	Public                 bool     `yaml:"public"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	AllowedOrigins         []string `yaml:"allowed_origins"`
}

type Persona struct {
	ID             string   `yaml:"id"`
	Subject        string   `yaml:"subject"`
	Email          string   `yaml:"email"`
	Name           string   `yaml:"name"`
	Roles          []string `yaml:"roles"`
	OrganizationID string   `yaml:"organization_id"`
	Memberships    []string `yaml:"memberships"`
}

// Load reads, decodes, and validates the configuration at path. The
// OAUTHSONAS_ACCESS_CODE environment variable replaces access_code when set,
// even with an empty value, and is validated like the file value, so a bad
// environment fails startup and --check-config instead of weakening the gate.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	var c Config
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("config must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if code, ok := os.LookupEnv("OAUTHSONAS_ACCESS_CODE"); ok {
		c.AccessCode = code
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate fills in defaults and then checks the whole configuration. It
// reports every problem it finds, not just the first.
func (c *Config) Validate() error {
	c.applyDefaults()
	var errs []error
	errs = append(errs, c.validateServer()...)
	errs = append(errs, c.Claims.validate()...)
	errs = append(errs, c.validateClients()...)
	errs = append(errs, c.validatePersonas()...)
	return errors.Join(errs...)
}

func (c *Config) applyDefaults() {
	c.AccessCode = strings.TrimSpace(c.AccessCode)
	if c.TokenTTL == 0 {
		c.TokenTTL = Duration(defaultTokenTTL)
	}
	if c.AuthorizationCodeTTL == 0 {
		c.AuthorizationCodeTTL = Duration(defaultAuthorizationCodeTTL)
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = Duration(defaultRefreshTokenTTL)
	}
	if c.Claims.Roles == "" {
		c.Claims.Roles = "roles"
	}
	if c.Claims.Memberships == "" {
		c.Claims.Memberships = "memberships"
	}
	if c.Claims.OrgID == "" {
		c.Claims.OrgID = "org_id"
	}
}

func (c *Config) validateServer() []error {
	var errs []error
	if u, ok := httpURL(c.Issuer); !ok || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		errs = append(errs, fmt.Errorf("issuer must be an absolute http(s) URL without query or fragment"))
	} else if u.Path != "" {
		errs = append(errs, fmt.Errorf("issuer must not include a path"))
	}
	if strings.TrimSpace(c.APIAudience) == "" {
		errs = append(errs, fmt.Errorf("api_audience is required"))
	} else if u, ok := httpURL(c.APIAudience); !ok || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		errs = append(errs, fmt.Errorf("api_audience must be an absolute http(s) URL without query or fragment"))
	}
	if strings.ContainsAny(c.AccessCode, " \t\r\n") {
		errs = append(errs, fmt.Errorf("access_code must not contain whitespace"))
	} else if c.AccessCode != "" && len(c.AccessCode) < minAccessCodeLength {
		errs = append(errs, fmt.Errorf("access_code must be at least %d characters", minAccessCodeLength))
	}
	for field, d := range map[string]Duration{"token_ttl": c.TokenTTL, "authorization_code_ttl": c.AuthorizationCodeTTL, "refresh_token_ttl": c.RefreshTokenTTL} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration", field))
		}
	}
	return errs
}

func (c *Config) validateClients() []error {
	if len(c.Clients) == 0 {
		return []error{fmt.Errorf("at least one client is required")}
	}
	var errs []error
	seen := map[string]bool{}
	for i, client := range c.Clients {
		if client.ID == "" || client.Name == "" {
			errs = append(errs, fmt.Errorf("client %d requires id and name", i))
		}
		if seen[client.ID] {
			errs = append(errs, fmt.Errorf("duplicate client id %q", client.ID))
		}
		seen[client.ID] = true
		if !client.Public {
			errs = append(errs, fmt.Errorf("client %q must set public: true; confidential clients are unsupported", client.ID))
		}
		if len(client.RedirectURIs) == 0 {
			errs = append(errs, fmt.Errorf("client %q requires at least one redirect_uri", client.ID))
		}
		for _, raw := range client.RedirectURIs {
			if u, ok := httpURL(raw); !ok || u.Fragment != "" {
				errs = append(errs, fmt.Errorf("client %q: redirect_uri must be an absolute http(s) URL without fragment", client.ID))
			}
		}
		for _, raw := range client.PostLogoutRedirectURIs {
			if u, ok := httpURL(raw); !ok || u.Fragment != "" {
				errs = append(errs, fmt.Errorf("client %q: post_logout_redirect_uri must be an absolute http(s) URL without fragment", client.ID))
			}
		}
		for _, raw := range client.AllowedOrigins {
			if u, ok := httpURL(raw); !ok || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
				errs = append(errs, fmt.Errorf("client %q: allowed_origin %q must be a scheme and host only", client.ID, raw))
			}
		}
	}
	return errs
}

func (c *Config) validatePersonas() []error {
	var errs []error
	allowedRoles := map[string]bool{}
	for _, role := range c.AllowedRoles {
		if role == "" {
			errs = append(errs, fmt.Errorf("allowed_roles must not contain an empty role"))
		}
		if allowedRoles[role] {
			errs = append(errs, fmt.Errorf("duplicate allowed role %q", role))
		}
		allowedRoles[role] = true
	}
	if len(c.Personas) == 0 {
		return append(errs, fmt.Errorf("at least one persona is required"))
	}
	ids, subjects := map[string]bool{}, map[string]bool{}
	for i, p := range c.Personas {
		if p.ID == "" || p.Subject == "" || p.Email == "" || p.Name == "" {
			errs = append(errs, fmt.Errorf("persona %d requires id, subject, email, and name", i))
		}
		if ids[p.ID] {
			errs = append(errs, fmt.Errorf("duplicate persona id %q", p.ID))
		}
		if subjects[p.Subject] {
			errs = append(errs, fmt.Errorf("duplicate persona subject %q", p.Subject))
		}
		ids[p.ID], subjects[p.Subject] = true, true
		if len(p.Roles) == 0 {
			errs = append(errs, fmt.Errorf("persona %q requires at least one role", p.ID))
		}
		for _, role := range p.Roles {
			if role == "" {
				errs = append(errs, fmt.Errorf("persona %q has an empty role", p.ID))
			} else if len(allowedRoles) != 0 && !allowedRoles[role] {
				errs = append(errs, fmt.Errorf("persona %q has unsupported role %q", p.ID, role))
			}
		}
	}
	return errs
}

func (c *Claims) validate() []error {
	var errs []error
	names := []struct{ field, value string }{
		{"claims.roles", c.Roles},
		{"claims.memberships", c.Memberships},
		{"claims.org_id", c.OrgID},
	}
	seen := map[string]string{}
	for _, name := range names {
		if strings.TrimSpace(name.value) != name.value || name.value == "" {
			errs = append(errs, fmt.Errorf("%s must be a non-empty claim name", name.field))
		} else if strings.ContainsAny(name.value, " \t\r\n") {
			errs = append(errs, fmt.Errorf("%s must not contain whitespace", name.field))
		}
		if other, ok := seen[name.value]; ok {
			errs = append(errs, fmt.Errorf("%s and %s must use distinct claim names", other, name.field))
		}
		seen[name.value] = name.field
		if reservedClaims[name.value] {
			errs = append(errs, fmt.Errorf("%s %q collides with a standard JWT/OIDC claim name", name.field, name.value))
		}
	}
	return errs
}

// reservedClaims are names the server or the OIDC/JWT specs already use.
var reservedClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"auth_time": true, "nonce": true, "acr": true, "amr": true, "azp": true,
	"at_hash": true, "c_hash": true,
	"email": true, "email_verified": true, "name": true,
	"client_id": true, "scope": true,
	"kid": true, "alg": true, "typ": true,
}

// httpURL parses raw as an absolute http(s) URL with a host and no userinfo.
func httpURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false
	}
	return u, true
}
