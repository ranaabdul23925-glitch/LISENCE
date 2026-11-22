# ShopPOS License Server

The default server is a Node.js PostgreSQL service. The legacy SQLite service is preserved for local compatibility and can be started explicitly with `npm run start:sqlite`; it is not the PostgreSQL production backend. The desktop POS app continues to use its existing local SQLite databases.

The PostgreSQL service uses the existing seven-table license schema in Supabase. It never resets or imports those tables. On startup it validates the existing schema, seeds plans only when the plans table is empty, and additively creates `admin_sessions` and `request_rate_limits` if they do not exist. The database role therefore needs permission to create tables in the selected schema on first startup. Existing records and plan rows are not changed by initialization.

## PostgreSQL environment

Configure these values in a trusted process environment or hosting secret manager. The server does not load `.env` files.

| Variable | Required | Notes |
|---|---|---|
| `SHOPPOS_DATABASE_URL` | Yes | Supabase PostgreSQL connection URL. Keep server-side. TLS certificate verification is enabled; SSL query parameters are normalized so they cannot override server SSL settings. |
| `SHOPPOS_DATABASE_CA_CERT_BASE64` | Production | Base64-encoded Supabase PEM CA certificate from the project's Database Settings → SSL Configuration. Required in production; local development may omit it and use Node.js system trust roots. Certificate verification remains enabled in both cases. |
| `LICENSE_SIGNING_PRIVATE_KEY` | Yes | Active Ed25519 PKCS#8 PEM signing key. Keep it server-side; literal `\n` sequences are accepted. Newly issued tokens are signed only by this key. |
| `LICENSE_TRUSTED_PUBLIC_KEYS_JSON` | No | JSON array of up to eight additional Ed25519 SPKI PEM public keys trusted for verifying existing tokens during an approved rotation. The active key's public key is trusted automatically. Keep old keys until an explicit retirement decision. |
| `LICENSE_ADMIN_USERS_JSON` | Yes | Existing administrator configuration as JSON. Each administrator needs a unique ID, unique high-entropy bearer token, and supported role set. |
| `LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON` | No | Optional server-side Secret containing additional admins accepted only by the temporary `GET /api/health?diagnostic=signing-key` endpoint. Entries use the same schema and validation as `LICENSE_ADMIN_USERS_JSON`, must have unique IDs and tokens across both lists, and require `licenses:manage` for this diagnostic. |
| `LICENSE_PLANS_JSON` | Yes | Owner-approved plan JSON. It seeds the database only when no plans exist. Keep configured plan IDs compatible with existing licenses. |
| `LICENSE_OFFLINE_GRACE_DAYS` | No | Signed desktop offline grace, defaults to 7, and must be 0–90. |
| `LICENSE_HOST` | No | Long-running server bind address; defaults to loopback in development and `0.0.0.0` in production. |
| `LICENSE_PORT` / `PORT` | No | Long-running server port; `LICENSE_PORT` takes precedence. Vercel manages function ports. |
| `NODE_ENV` | No | Set to `production` for a long-running production server; secure cookies and seven-day plan grace enforcement are enabled. |
| `PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET` | Sandbox only | Optional 32-character minimum secret for the test webhook adapter. That adapter is rejected when `NODE_ENV=production`; this is not a payment provider credential. |

The server verifies incoming tokens against the active key and `LICENSE_TRUSTED_PUBLIC_KEYS_JSON`, but signs new tokens only with the active key. Desktop verification accepts `SHOPPOS_LICENSE_PUBLIC_KEYS_JSON`, the legacy `SHOPPOS_LICENSE_PUBLIC_KEY`, and keys packaged in `desktop/license-public-keys.json`; keys are trusted only from these configured sources, never from an API response. Preserve old public keys through an explicitly approved overlap and retirement plan. Never set the private key or database URL in browser or desktop variables.

## Long-running Node server

Install the lockfile dependencies and start the PostgreSQL backend from this directory:

```powershell
npm ci
npm start
```

`npm start` runs `node postgres/server.cjs`. Use a PostgreSQL test database for local integration testing; do not point development or tests at production. Terminate internet traffic at an HTTPS ingress or reverse proxy. The health endpoint is `GET /v1/health`.

The SQLite implementation is available only as a compatibility path:

```powershell
npm run start:sqlite
```

That process uses `LICENSE_DATABASE_PATH` and is not shared with the PostgreSQL service.

## Vercel backend

Deploy this directory as its own Vercel project. Do not set the main ShopPOS Next.js project root to this directory: the root frontend has `output: "export"` and remains a separate static deployment.

1. Create a separate Vercel project from the repository and set its **Root Directory** to `license-server`.
2. Use Node.js 20 or newer. The project includes `vercel.json`, one catch-all Node function, and rewrites that preserve the existing `/v1/*` and `/admin/*` paths.
3. Configure the required environment variables above in Vercel's server-side project settings. Do not put database URLs or signing/admin secrets in `NEXT_PUBLIC_*` variables, static files, or this repository.
4. For Preview deployments, use a dedicated isolated database and non-production credentials. Do not reuse production signing keys or license records for tests.
5. Deploy only after confirming the database schema, administrator credentials, existing signing key, plan configuration, and database backup/restore procedure with the project owner.
6. Confirm `GET https://<deployment-host>/v1/health` and the `/admin` dashboard over HTTPS. Do not issue customer licenses until the isolated end-to-end checks pass.

The Vercel adapter uses PostgreSQL-backed admin sessions and rate limits so these controls do not depend on one function process. The admin session cookie is HttpOnly, SameSite=Strict, Secure, and state-changing browser requests still require same-origin and CSRF validation. Direct administrator bearer-token API calls retain their existing roles.

## Desktop compatibility

The desktop API contract remains:

- `POST /v1/activate` returns `{ token, status }`.
- `POST /v1/status` refreshes a signed Ed25519 token and status.
- `POST /v1/deactivate` deactivates the bound local shop/device.
- `POST /v1/payments/submit` and `GET /v1/payments` use the existing desktop payment request formats.

Configure only the public `SHOPPOS_LICENSE_SERVER_URL` and matching `SHOPPOS_LICENSE_PUBLIC_KEY` in the desktop launch/build environment. The URL must be HTTPS outside localhost. Never expose the server private key, `SHOPPOS_DATABASE_URL`, administrator tokens, or database credentials to Electron renderer code.

## Database migration and backups

No Supabase connection or production migration is performed by these scripts or tests. The SQLite-to-Supabase migration script is a separate, one-way operator tool with a fixed source path and a guard that refuses non-empty destination tables; it is not part of application startup and must not be run against populated production tables.

The two support tables are additive. Startup creates them with `CREATE TABLE IF NOT EXISTS`; the seven existing licensing tables are only checked/read/updated by the service. Existing plans are not upserted or replaced at startup. Production startup requires the stored plan grace values to be exactly seven days.

PostgreSQL backup and restore are external operations. The admin backup/restore routes return HTTP 501 for this backend rather than writing to ephemeral function storage. Use Supabase-managed backups or an approved external `pg_dump`/`pg_restore` workflow, protect exported files, and test restore against a separate staging database. Local SQLite backup files do not back up Supabase.

The only registered webhook adapter is a sandbox-only test adapter. No live payment gateway, card processing, production webhook credential, or real billing is implemented. Do not enable the test adapter for production payments.

## Validation

Run from the repository root:

```powershell
npm test
npm run lint
npm run typecheck
npm run build
```

`license-server/postgres/service.test.cjs` uses an in-memory PostgreSQL test double and verifies service/API contracts, token compatibility, transactions, locking intent, payment processing, idempotency, persistent-session behavior, and configuration. It does not replace testing against a disposable PostgreSQL/Supabase staging database. No tests here connect to a real Supabase project.

## Deployment status and remaining gates

The backend code and deployment adapter are prepared locally, but production readiness is **not verified**: there has been no Supabase connection, Vercel deployment, real schema introspection, server-side secret configuration, isolated live PostgreSQL test, payment-provider verification, or production backup/restore exercise. Complete those steps with project-owner approval before launch.
