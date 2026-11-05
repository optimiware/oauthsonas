package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateListenAddress(t *testing.T) {
	t.Setenv("OAUTHSONAS_ALLOW_NON_LOOPBACK", "")
	for _, address := range []string{"127.0.0.1:8181", "[::1]:8181", "localhost:8181"} {
		if err := validateListenAddress(address); err != nil {
			t.Errorf("validateListenAddress(%q) returned %v", address, err)
		}
	}
	if err := validateListenAddress("0.0.0.0:8181"); err == nil {
		t.Fatal("non-loopback address was accepted")
	}
}

func TestValidateListenAddressAllowsExplicitOverride(t *testing.T) {
	t.Setenv("OAUTHSONAS_ALLOW_NON_LOOPBACK", "true")
	if err := validateListenAddress("0.0.0.0:8181"); err != nil {
		t.Fatalf("explicit override was rejected: %v", err)
	}
}

func TestNewLogger(t *testing.T) {
	for _, tc := range []struct {
		format, level string
		ok            bool
	}{
		{"json", "info", true},
		{"text", "DEBUG", true},
		{"json", "warn", true},
		{"yaml", "info", false},
		{"json", "verbose", false},
	} {
		_, err := newLogger(tc.format, tc.level)
		if (err == nil) != tc.ok {
			t.Errorf("newLogger(%q, %q) error = %v, want ok=%v", tc.format, tc.level, err, tc.ok)
		}
	}
}

func TestHealthcheckURL(t *testing.T) {
	for listen, want := range map[string]string{
		"127.0.0.1:8181": "http://127.0.0.1:8181/healthz",
		"0.0.0.0:8181":   "http://127.0.0.1:8181/healthz",
		":8181":          "http://127.0.0.1:8181/healthz",
		"[::]:8181":      "http://[::1]:8181/healthz",
		"localhost:9000": "http://localhost:9000/healthz",
	} {
		got, err := healthcheckURL(listen)
		if err != nil || got != want {
			t.Errorf("healthcheckURL(%q) = %q, %v; want %q", listen, got, err, want)
		}
	}
	if _, err := healthcheckURL("no-port"); err == nil {
		t.Error("address without a port accepted")
	}
}

func TestRunHealthcheck(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("probed %s", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	listen := strings.TrimPrefix(server.URL, "http://")

	if err := runHealthcheck(listen); err != nil {
		t.Fatalf("healthy server reported unhealthy: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := runHealthcheck(listen); err == nil {
		t.Fatal("503 reported healthy")
	}
	server.Close()
	if err := runHealthcheck(listen); err == nil {
		t.Fatal("closed server reported healthy")
	}
}
