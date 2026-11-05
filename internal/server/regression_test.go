package server

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
)

func twoClientProvider(t *testing.T) *testProvider {
	t.Helper()
	return newTestProviderConfig(t, 5*time.Minute, func(c *config.Config) {
		c.Clients = append(c.Clients, config.Client{
			ID: "other", Name: "Other", Public: true,
			RedirectURIs:           []string{"http://127.0.0.1:6000/callback"},
			PostLogoutRedirectURIs: []string{"http://127.0.0.1:6000/"},
		})
	})
}

func TestIDTokenHintIdentifiesClient(t *testing.T) {
	t.Parallel()
	p := twoClientProvider(t)
	_, result := fullFlow(t, p, "acme-admin")
	idToken := result["id_token"].(string)

	clientID, err := p.srv.clientIDFromIDTokenHint(idToken)
	if err != nil || clientID != "dashboard" {
		t.Fatalf("clientIDFromIDTokenHint = %q, %v; want dashboard", clientID, err)
	}

	// A token issued to "dashboard" must not unlock "other"'s logout redirect.
	client := browserClient(t)
	response, err := client.Get(p.baseURL + "/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://127.0.0.1:6000/"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-client logout redirect status = %d, want 400", response.StatusCode)
	}

	response, err = client.Get(p.baseURL + "/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://127.0.0.1:5173/"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("own-client logout redirect status = %d, want 302", response.StatusCode)
	}
}

func TestIDTokenHintRejectsForgedToken(t *testing.T) {
	t.Parallel()
	p := twoClientProvider(t)
	other := twoClientProvider(t)
	_, result := fullFlow(t, other, "acme-admin")

	if id, err := p.srv.clientIDFromIDTokenHint(result["id_token"].(string)); err == nil {
		t.Fatalf("token signed by another server accepted for client %q", id)
	}
}

// Run with -race: cleanup must not touch fosite's maps while requests do.
func TestCleanupIsSafeDuringTraffic(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	stop := make(chan struct{})
	var cleaners sync.WaitGroup
	cleaners.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				p.srv.cleanupStore()
			}
		}
	})

	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			for range 10 {
				params := validAuthorizeParams()
				params.Set("login_hint", "acme-admin")
				response, err := client.Get(authorizeURL(p.baseURL, params))
				if err != nil {
					t.Error(err)
					return
				}
				response.Body.Close()
				location, err := url.Parse(response.Header.Get("Location"))
				if err != nil || location.Query().Get("code") == "" {
					t.Errorf("no code in %q", response.Header.Get("Location"))
					return
				}
				result := exchange(t, p, client, location.Query().Get("code"), verifier)
				token, _ := result["access_token"].(string)
				request, _ := http.NewRequest(http.MethodGet, p.baseURL+"/userinfo", nil)
				request.Header.Set("Authorization", "Bearer "+token)
				if r, err := client.Do(request); err == nil {
					r.Body.Close()
				}
			}
		})
	}
	workers.Wait()
	close(stop)
	cleaners.Wait()
}

func TestCloseStopsCleanupAndIsIdempotent(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, 5*time.Minute)
	p.srv.Close()
	p.srv.Close()
}
