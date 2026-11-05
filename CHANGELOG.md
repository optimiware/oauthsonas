# Changelog

## 1.5.0 - 2026-11-05

### Upgrade notes

- **Container health check.** The image now defines a `HEALTHCHECK` that probes
  `0.0.0.0:8181`. If you override `--listen` with another port, the container
  will be reported `unhealthy` (and Compose `service_healthy` will never be
  satisfied) until you override the check too, for example
  `healthcheck: { test: ["CMD", "/usr/local/bin/oauthsonas", "--healthcheck", "--listen", "0.0.0.0:9000"] }`.
  Docker honors the image's `HEALTHCHECK`; Podman only does with `--format docker`.
- **Invalid `--log-level` / `--log-format` now exit with status 2** instead of
  silently using a default.
- **Logout is stricter.** With an `id_token_hint` signed by this server, a
  `client_id` that does not match the token's audience fails with `400`, and the
  `post_logout_redirect_uri` must belong to the hint's client. Hints signed by a
  previous run are still ignored with a warning.
- `prompt=none` now always returns `login_required` (this server keeps no login
  session); unknown `prompt` values return `invalid_request`.
- `HEAD /oauth2/auth` returns `405`.
- The token endpoint ignores query-string parameters (POST body only).
- The interaction cookie is `Secure` when `issuer` is `https`.
- Config errors are logged one per line with the message `invalid config`
  (previously a single `failed to load config` entry). Anything that matched on
  the old message needs updating.
- Go 1.26.10 / 1.27.3 pick up standard-library security fixes (`net/http`,
  HTTP/2, `crypto/tls`, `crypto/x509`). The previous image was built with 1.27.0.
- `golang.org/x/crypto` is pinned to a commit after v0.58.0 that fixes advisory
  GO-2026-5932 (the `openpgp` package, which oauthsonas never imported); no
  tagged release contains the fix yet. Move back to a tag once one exists.

### Fixed

- Background cleanup raced with in-flight requests on fosite's in-memory store
  (a fatal concurrent map access under load). All store access now goes through
  one lock; cleanup also prunes the request-ID maps and keeps rotated refresh
  tokens until their own expiry.
- `id_token_hint` was never verified (the private key was passed to the
  verifier), so logout could not identify the client. It is now verified with
  the public key and constrains the allowed `post_logout_redirect_uri`.
- `Server.Close()` stops the cleanup goroutine.
- The README quick start used an `OIDC_AUDIENCE` that the example config rejects.
- `HEAD /oauth2/auth?login_hint=...` matched the `GET` route and issued an
  authorization code, so link previewers or probes could trigger a login.
- `token_ttl: ""` (an empty duration) is accepted again and keeps the default.
- README: authorize redirects are `303 See Other`, not `302`.

### Changed

- `prompt=none` returns `login_required` immediately instead of rendering the
  picker; unknown `prompt` values return `invalid_request`.
- `/logout` accepts `POST` as well as `GET`.
- `/userinfo` error responses include CORS headers for registered origins and
  expose `WWW-Authenticate`.
- The token endpoint reads parameters from the POST body only (matching fosite)
  and request bodies are limited to 64 KiB.
- The interaction cookie is `Secure` when the issuer is `https`, like the gate
  cookie.
- The access-code gate logs successful and rejected attempts.
- Config: `token_ttl`, `authorization_code_ttl`, and `refresh_token_ttl` must be
  Go duration strings; validation reports every problem at once;
  `OAUTHSONAS_ACCESS_CODE` is applied inside `config.Load`.
- Unknown `--log-format` / `--log-level` values are rejected instead of ignored.
- Replaced `gopkg.in/yaml.v3` with the maintained `go.yaml.in/yaml/v3`.

### Added

- `--healthcheck` flag and a container `HEALTHCHECK` (the image has no shell or `curl`).
- [docs/e2e-stack.md](docs/e2e-stack.md): Compose and Playwright guide.
- CI gates for `gofmt`, `go mod tidy`, and `staticcheck`; the Go version is
  read from `go.mod`.

### Internal

- `internal/server` is split by concern (authorize, gate, token, userinfo,
  logout, session, store, http helpers); HTML templates are embedded files;
  routes use method-aware patterns.
- The multi-arch image is cross-compiled instead of built under QEMU.
- `test/e2e/smoke.sh` performs a full login against the image and waits for the
  container's `HEALTHCHECK` to report healthy (`REQUIRE_HEALTHCHECK=1` makes a
  missing check a failure; CI sets it).
- CI runs `govulncheck` on the built image binary as well as the source, so the
  image's Go toolchain cannot drift from `go.mod` unnoticed.
