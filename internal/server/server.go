// Package server implements the oauthsonas OpenID Connect provider.
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

const cleanupInterval = 5 * time.Minute

type Server struct {
	config        *config.Config
	provider      fosite.OAuth2Provider
	store         *storage.MemoryStore
	storeMu       sync.Mutex // guards every access to store; see cleanupStore
	key           *jose.JSONWebKey
	clients       map[string]config.Client
	personas      map[string]config.Persona
	personaList   []config.Persona // sorted by id, for the picker
	discoveryDoc  map[string]interface{}
	interactions  *ttlStore[pendingAuthorize]
	gate          *ttlStore[struct{}]
	accessCode    string
	secureCookies bool
	logger        *slog.Logger
	version       string
	startTime     time.Time
	cleanupDone   chan struct{}
	closeOnce     sync.Once
}

// oidcClient is a public OpenID Connect client restricted to query responses.
type oidcClient struct {
	*fosite.DefaultOpenIDConnectClient
	responseModes []fosite.ResponseModeType
}

func (c *oidcClient) GetResponseModes() []fosite.ResponseModeType { return c.responseModes }

func New(c *config.Config, logger *slog.Logger, version string) (*Server, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	kid, err := randomString(12)
	if err != nil {
		return nil, err
	}
	key := &jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate server secret: %w", err)
	}

	store := storage.NewMemoryStore()
	clients := registerClients(store, c)
	personas := make(map[string]config.Persona, len(c.Personas))
	personaList := make([]config.Persona, 0, len(c.Personas))
	for _, p := range c.Personas {
		personas[p.ID] = p
		personaList = append(personaList, p)
	}
	sort.Slice(personaList, func(i, j int) bool { return personaList[i].ID < personaList[j].ID })

	s := &Server{
		config:        c,
		provider:      newProvider(c, store, key, secret),
		store:         store,
		key:           key,
		clients:       clients,
		personas:      personas,
		personaList:   personaList,
		discoveryDoc:  discoveryDocument(c.Issuer, []string{c.Claims.Roles, c.Claims.OrgID, c.Claims.Memberships}),
		interactions:  newTTLStore[pendingAuthorize](interactionTTL),
		gate:          newTTLStore[struct{}](gateSessionTTL),
		accessCode:    c.AccessCode,
		secureCookies: strings.HasPrefix(c.Issuer, "https://"),
		logger:        logger,
		version:       version,
		startTime:     time.Now(),
		cleanupDone:   make(chan struct{}),
	}
	s.startCleanup()
	return s, nil
}

// registerClients adds every configured client to store as a public
// authorization-code client and returns them keyed by id.
func registerClients(store *storage.MemoryStore, c *config.Config) map[string]config.Client {
	clients := make(map[string]config.Client, len(c.Clients))
	for _, client := range c.Clients {
		clients[client.ID] = client
		store.Clients[client.ID] = &oidcClient{
			DefaultOpenIDConnectClient: &fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID:            client.ID,
					RedirectURIs:  client.RedirectURIs,
					Public:        true,
					GrantTypes:    []string{"authorization_code", "refresh_token"},
					ResponseTypes: []string{"code"},
					Scopes:        supportedScopes,
					Audience:      []string{c.APIAudience},
				},
				TokenEndpointAuthMethod: "none",
			},
			responseModes: []fosite.ResponseModeType{fosite.ResponseModeQuery},
		}
	}
	return clients
}

func newProvider(c *config.Config, store *storage.MemoryStore, key *jose.JSONWebKey, secret []byte) fosite.OAuth2Provider {
	fc := &fosite.Config{
		GlobalSecret:                   secret,
		IDTokenIssuer:                  c.Issuer,
		AccessTokenIssuer:              c.Issuer,
		AccessTokenLifespan:            c.TokenTTL.D(),
		IDTokenLifespan:                c.TokenTTL.D(),
		AuthorizeCodeLifespan:          c.AuthorizationCodeTTL.D(),
		RefreshTokenLifespan:           c.RefreshTokenTTL.D(),
		EnforcePKCE:                    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       fosite.ExactAudienceMatchingStrategy,
		RefreshTokenScopes:             []string{"offline_access"},
		JWTScopeClaimKey:               jwt.JWTScopeFieldString,
	}
	keyGetter := func(context.Context) (interface{}, error) { return key, nil }
	hmacStrategy := compose.NewOAuth2HMACStrategy(fc)
	strategy := compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fc),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fc),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}
	return compose.Compose(fc, store, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
}

// Close stops background cleanup. It is safe to call more than once.
func (s *Server) Close() {
	s.closeOnce.Do(func() { close(s.cleanupDone) })
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("OPTIONS /.well-known/openid-configuration", s.preflight(http.MethodGet))
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("OPTIONS /.well-known/jwks.json", s.preflight(http.MethodGet))
	mux.HandleFunc("GET /oauth2/auth", s.authorize)
	mux.HandleFunc("POST /oauth2/auth/select", s.selectPersona)
	mux.HandleFunc("POST /oauth2/gate", s.gateSubmit)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("OPTIONS /oauth2/token", s.preflight(http.MethodPost))
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("POST /userinfo", s.userinfo)
	mux.HandleFunc("OPTIONS /userinfo", s.preflight(http.MethodGet, http.MethodPost))
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("POST /logout", s.logout)
	return s.logRequest(mux)
}
