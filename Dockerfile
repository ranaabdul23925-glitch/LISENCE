# ShopPOS license server (PostgreSQL mode) container image.
#
# This image runs the opt-in PostgreSQL-backed license service. It is a
# deployment artifact only; it is never used by the ShopPOS desktop app.
# Secrets (signing key, plan JSON, admin tokens) and the database URL are
# supplied at runtime via environment variables or a secret manager. No .env
# file, database, backup, or private key is ever baked into the image.
#
# Build (from the license-server directory):
#   docker build -t shoppos-license-server .
# Run:
#   docker run --rm -p 8787:8787 \
#     -e NODE_ENV=production \
#     -e POSTGRES_DATABASE_URL=postgresql://... \
#     -e LICENSE_SIGNING_PRIVATE_KEY=... \
#     -e LICENSE_PLANS_JSON='[]' \
#     -e LICENSE_ADMIN_USERS_JSON='[]' \
#     shoppos-license-server

FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    LICENSE_HOST=0.0.0.0

WORKDIR /app

# Install production dependencies first for better layer caching. Only runtime
# packages are installed; no dev tooling ships in the image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the server sources, migrations, admin dashboard and startup entry point.
COPY license-server.cjs start-postgres.cjs postgres-adapter.cjs sqlite-to-postgres.cjs sqlite-migrate.cjs payments-gateway.cjs signing-keys.cjs ./
COPY migrations ./migrations
COPY admin-dashboard ./admin-dashboard

# Run as an unprivileged user.
RUN useradd --system --uid 10001 --create-home shoppos \
    && chown -R shoppos:shoppos /app
USER shoppos

EXPOSE 8787

# The entry point validates configuration and starts the PostgreSQL-backed
# service, handling SIGINT/SIGTERM for graceful HTTP and pool shutdown.
CMD ["node", "start-postgres.cjs"]