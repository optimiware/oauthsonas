# Using oauthsonas in an end-to-end test stack

This guide wires oauthsonas into a Docker Compose stack with a backend and a
Playwright browser test. The same ideas apply to any runner.

## The one rule: a single issuer URL

OIDC issuer matching is exact. The `iss` claim, the discovery document, and the
URL your relying party was configured with must all be the same string, and
**both the browser and the backend must be able to reach it**. In Compose the
simplest way is to run the browser inside the Compose network and use the
service name:

```yaml
# oauthsonas.yaml
issuer: http://oauthsonas:8181
api_audience: https://api.example.test
clients:
  - id: web
    name: Web App
    public: true
    redirect_uris: [http://web:3000/auth/callback]
    post_logout_redirect_uris: [http://web:3000/]
    allowed_origins: [http://web:3000]
personas:
  - id: admin
    subject: oauthsonas|admin
    email: admin@example.test
    name: Admin
    roles: [admin]
```

Validate it before starting the stack:

```sh
oauthsonas --config oauthsonas.yaml --check-config
```

## Compose

```yaml
services:
  oauthsonas:
    image: ghcr.io/optimiweb/oauthsonas:1   # pin a version in real projects
    command: ["--config", "/config/oauthsonas.yaml", "--listen", "0.0.0.0:8181", "--log-format", "text"]
    environment:
      OAUTHSONAS_ALLOW_NON_LOOPBACK: "true"   # required to bind 0.0.0.0
    volumes:
      - ./oauthsonas.yaml:/config/oauthsonas.yaml:ro
    healthcheck:   # needed with Podman or a custom --listen; Docker images define one already
      test: ["CMD", "/usr/local/bin/oauthsonas", "--healthcheck", "--listen", "0.0.0.0:8181"]
      interval: 2s
      retries: 15

  web:
    build: .
    environment:
      OIDC_AUTHORITY: http://oauthsonas:8181
      OIDC_CLIENT_ID: web
    depends_on:
      oauthsonas:
        condition: service_healthy

  e2e:
    image: mcr.microsoft.com/playwright:v1.50.0-noble
    working_dir: /e2e
    volumes: [./e2e:/e2e]
    environment:
      BASE_URL: http://web:3000
    depends_on: [web]
    command: npx playwright test
```

Do not publish the oauthsonas port beyond loopback. If your tests run on the
host instead, publish `127.0.0.1:8181:8181`, use `http://127.0.0.1:8181` as the
issuer everywhere, and make the backend container reach it through the same
address (for example `network_mode: host`).

## Signing in from Playwright

Two options. Both exercise the real browser flow; they only differ in how the
persona is chosen.

**Click the picker.** The selectors are stable (see the README's Browser
automation section):

```ts
import { test, expect } from '@playwright/test';

test('admin can sign in', async ({ page }) => {
  await page.goto('/login');                       // the app redirects to oauthsonas
  await page.getByTestId('persona-select-admin').click();
  await expect(page).toHaveURL(/\/auth\/callback/);
  await expect(page.getByText('Admin')).toBeVisible();
});
```

**Skip the picker with `login_hint`.** Have the app add
`login_hint=<persona id>` to its authorize request (with `oidc-client-ts`:
`extraQueryParams: { login_hint: 'admin' }`). The authorize request then
redirects straight back with a code, so no UI interaction is needed. Make the
hint test-only, for instance from an environment variable.

## Shared instances and the access code

If you must expose an instance beyond one machine, set `access_code`
(or `OAUTHSONAS_ACCESS_CODE`). Browsers then see a code form first:

```ts
await page.getByTestId('access-code-input').fill(process.env.OAUTHSONAS_ACCESS_CODE!);
await page.getByTestId('access-code-submit').click();
```

`login_hint` does not bypass the gate. This is a perimeter for a test
instance, not authentication; never use it for anything real.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `issuer mismatch` in the app | The app's authority differs from `issuer` (`localhost` vs `127.0.0.1`, missing port, trailing slash). |
| Browser cannot reach `http://oauthsonas:8181` | The browser runs on the host; use the loopback setup above or run it inside the network. |
| Token validation fails after restarting oauthsonas | The signing key is regenerated on every start; restart dependent services too, or clear their JWKS cache. |
| `redirect_uri must exactly match` | Registered `redirect_uris` are exact-match, including path and any query. |
| CORS error from the browser | Add the page's origin to the client's `allowed_origins` (scheme and host only). |
| `prompt=none` / silent renew fails with `login_required` | Expected: oauthsonas keeps no session. Use refresh tokens (`offline_access`). |
