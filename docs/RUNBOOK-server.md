# Runbook — `cortex serve` with PostgreSQL

Operating the server deployment: two containers, `cortex` and `cortex-db`, defined by
`docs/examples/docker-compose.server.yml`.

Every command here runs from the repository root on the server. Compose is always invoked the same
way — `--project-directory .` is what makes the relative volume paths resolve to the root instead of
to `docs/examples/`:

```bash
docker compose -f docs/examples/docker-compose.server.yml --project-directory . <cmd>
```

Shortened to `COMPOSE` below:

```bash
alias COMPOSE='docker compose -f docs/examples/docker-compose.server.yml --project-directory .'
```

## What lives where

| | Where | Lost if you lose it |
|---|---|---|
| Issued API keys, analyses, SARIF | `cortex-db` → volume `cortex_cortex-db-data` | every client key; they cannot be re-issued with the same secret |
| Per-project reconcile state, uploaded archives | `cortex` → volume `cortex_cortex-data` | every finding looks new on the next scan |
| Bootstrap key, webhook secret, DB password | `.env`, mode 600 | see *Rotating the database password* |

`cortex-db` publishes no port. It is reachable only from the `cortex` container over the compose
network, and from you via `COMPOSE exec`.

## Bringing it up

```bash
./scripts/deploy-server.sh --domain sast.example.com
```

It generates `.env` (once — a second run keeps the existing credentials), copies
`docs/examples/server.yaml` to `./server.yaml` if there is none, pulls the image, starts both
containers and checks that an unauthenticated request is refused.

By hand:

```bash
COMPOSE up -d          # cortex waits for cortex-db to report healthy
COMPOSE ps             # both Up, cortex-db "(healthy)"
curl -fsS http://127.0.0.1:8080/healthz
```

There is no migration step. Cortex applies its own schema on connect, with
`CREATE TABLE IF NOT EXISTS`, so a fresh database needs to exist and nothing needs to be run in it.

Cortex listens on `127.0.0.1:8080` only. Put a TLS-terminating proxy in front of it — the API keys
travel in an `Authorization` header.

## Issuing the first client key

`.env` holds a bootstrap key (`CLIENT_ACME_KEY`) that never expires. It exists so the server has a
usable credential and will start; it is not how a client is given access.

```bash
COMPOSE exec cortex cortex keys issue --client acme --ttl 90d
```

The secret is printed once and stored only as a hash — there is no way to read it back. Hand it over
out of band, then:

```bash
COMPOSE exec cortex cortex keys list          # what exists, and when each one ends
COMPOSE exec cortex cortex keys revoke <id>   # stops working immediately, no restart
```

A client uses it like this:

```bash
curl -X POST https://sast.example.com/api/v1/analyses \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"repository":"github.com/acme/api","ref":"main","project":"acme-api"}'
```

## Backup

One database, one dump. Custom format, because it restores selectively and compresses the SARIF
blobs:

```bash
COMPOSE exec -T cortex-db \
  pg_dump -U cortex -d cortex --format=custom \
  > "cortex-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

`-T` matters: without it Docker allocates a TTY and mangles the binary stream.

Copy the dump off this host. A backup sitting on the same disk as the volume it came from is not a
backup. Rotate them — the estate already has ten unrotated backup directories accumulated in `/root`
on another box.

Back up `.env` separately and encrypted. The dump without the password is restorable; the deployment
without `.env` is not startable.

## Restore

Into the running database, replacing what is there:

```bash
COMPOSE stop cortex        # nothing writing while the restore runs
COMPOSE exec -T cortex-db \
  pg_restore -U cortex -d cortex --clean --if-exists < cortex-20260917T101500Z.dump
COMPOSE start cortex
```

Into an empty one (the volume was lost): bring `cortex-db` up first, let it initdb, then restore.
Cortex does not need to have run — `pg_restore` brings the tables with it.

```bash
COMPOSE up -d cortex-db
COMPOSE exec -T cortex-db pg_restore -U cortex -d cortex --clean --if-exists < <dump>
COMPOSE up -d
```

Two things a restore does **not** bring back, because they are not in the database: the per-project
reconcile state under `/var/lib/cortex` (restore the `cortex-data` volume, or accept that the next
scan of each project reports everything as new), and `.env`.

## When cortex cannot reach the database

Cortex applies its schema on connect and **exits** if it cannot — it does not fall back to files.
`COMPOSE ps` shows `cortex` restarting; `COMPOSE logs cortex` shows one of `connect to postgres`,
`reach postgres`, or `apply api key schema`.

Work down this list:

1. **Is the database healthy?**
   ```bash
   COMPOSE ps                    # cortex-db should say (healthy)
   COMPOSE logs --tail=50 cortex-db
   ```
   A `cortex-db` stuck in `starting` for more than a minute is usually initdb failing on a
   non-empty, foreign data directory — check the volume is the one you think it is.

2. **Does the password match?** This is the common one. The password is baked into the data
   directory at initdb; editing `CORTEX_DB_PASSWORD` in `.env` afterwards changes what cortex sends,
   not what the database expects. The log says `password authentication failed for user "cortex"`.
   Either put the old value back, or rotate properly (below).

3. **Does the DSN point at the service?** `./server.yaml` must have, uncommented:
   ```yaml
   database: postgres://cortex:${CORTEX_DB_PASSWORD}@cortex-db:5432/cortex?sslmode=disable
   ```
   `cortex-db` is the compose service name, resolved on the compose network — not `localhost`, which
   inside the container is the container itself. `sslmode=require` fails here: the stock Postgres
   image serves no TLS.

4. **Did the variable reach the container?**
   ```bash
   COMPOSE exec cortex printenv CORTEX_DB_PASSWORD
   ```
   Empty means it is missing from `.env`. An undefined `${VAR}` in the config expands to empty, so
   the DSN ends up with no password rather than staying literal.

5. **Prove the path end to end**, from inside the cortex container:
   ```bash
   COMPOSE exec cortex python3 -c \
     "import socket; socket.create_connection(('cortex-db', 5432), 5); print('reachable')"
   COMPOSE exec cortex-db psql -U cortex -d cortex -c '\dt'
   ```
   The image has no `nc`; it does have Python, for the Bandit and Semgrep adapters.
   The second should list `cortex_analyses`, `cortex_api_keys` and `cortex_project_state`.

**Silent failure to watch for:** if `server.database` is commented out, cortex starts perfectly and
writes to files under `data_dir` while `cortex-db` sits there empty. Nothing is broken and nothing
warns you, until a redeploy or a second instance. `deploy-server.sh` checks for this; if you edited
`server.yaml` by hand, check it yourself.

## Rotating the database password

Change it in the database first, then in `.env` — not the other way round.

```bash
NEW=$(openssl rand -hex 32)
COMPOSE exec -T cortex-db psql -U cortex -d cortex \
  -c "ALTER USER cortex WITH PASSWORD '$NEW';"
sed -i "s/^CORTEX_DB_PASSWORD=.*/CORTEX_DB_PASSWORD=$NEW/" .env
COMPOSE up -d --force-recreate cortex
```

Only `cortex` is recreated: `POSTGRES_PASSWORD` is read by the database at initdb and ignored on
every start after it, so recreating `cortex-db` would achieve nothing and risks a restore.
