package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/optimiweb/oauthsonas/internal/server"
)

var version = "devel"

func main() {
	configPath := flag.String("config", "config.example.yaml", "path to YAML configuration")
	listen := flag.String("listen", "127.0.0.1:8181", "listen address")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz on the --listen address and exit 0 when healthy (for container health checks)")
	logFormat := flag.String("log-format", "json", "log format: text or json")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	logger, err := newLogger(*logFormat, *logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if flag.NArg() != 0 {
		logger.Error("unexpected positional arguments", "args", strings.Join(flag.Args(), " "))
		os.Exit(1)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *healthcheck {
		if err := runHealthcheck(*listen); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	c, err := config.Load(*configPath)
	if err != nil {
		logErrors(logger, "invalid config", err)
		os.Exit(1)
	}
	if *checkConfig {
		logger.Info("configuration is valid", "path", *configPath)
		return
	}
	if err := validateListenAddress(*listen); err != nil {
		logger.Error("invalid listen address", "error", err)
		os.Exit(1)
	}
	s, err := server.New(c, logger, version)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	defer s.Close()
	logger.Info("starting developer OIDC provider", "issuer", c.Issuer, "listen", *listen)
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(listener) }()
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve failed", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}
}

// logErrors logs each error of an errors.Join result as its own entry.
func logErrors(logger *slog.Logger, msg string, err error) {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			logger.Error(msg, "error", e)
		}
		return
	}
	logger.Error(msg, "error", err)
}

func newLogger(format, level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q: want debug, info, warn, or error", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(format) {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	}
	return nil, fmt.Errorf("invalid --log-format %q: want json or text", format)
}

// healthcheckURL turns a listen address into the /healthz URL a local probe
// should use; wildcard hosts probe loopback.
func healthcheckURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
		if ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func runHealthcheck(listen string) error {
	target, err := healthcheckURL(listen)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", target, response.Status)
	}
	return nil
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if os.Getenv("OAUTHSONAS_ALLOW_NON_LOOPBACK") == "true" {
		return nil
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing non-loopback listen address %q; set OAUTHSONAS_ALLOW_NON_LOOPBACK=true to acknowledge development-only exposure", address)
}
