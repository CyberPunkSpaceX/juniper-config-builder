# Installing EX Config Builder

## Docker Swarm (Portainer or CLI)

1. Pick the node that keeps the data volume, for example `CP-DOCKER-SWARM-01`.
2. Deploy:

   ```
   EXB_NODE=CP-DOCKER-SWARM-01 docker stack deploy -c deploy/exbuilder-stack.yml --with-registry-auth exbuilder
   ```

   In Portainer: Stacks > Add stack > Web editor, paste `deploy/exbuilder-stack.yml`,
   and add the environment variable `EXB_NODE`.
3. Open `http://<any-node>:8088`, sign in as `admin` / `admin` and choose a new password.
4. Behind an HTTPS reverse proxy, set `EXB_SECURE_COOKIES=true` and redeploy.

The image is private on GHCR while the repository is private, so the nodes
need `docker login ghcr.io` with a token that can read packages, and the deploy
needs `--with-registry-auth`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `EXB_DATA_DIR` | `/data` | Users, saved projects and the session key (SQLite) |
| `EXB_USERNAME` / `EXB_PASSWORD` / `EXB_PASSWORD_FILE` | | First admin on an empty database (otherwise admin / admin with a forced change) |
| `EXB_SECURE_COOKIES` | `false` | Send the session cookie over HTTPS only |
| `EXB_REQUIRE_2FA` | `false` | Everyone must set up an authenticator app |
| `EXB_SESSION_HOURS` | `12` | How long a sign-in lasts |
| `EXB_LOCKOUT_ATTEMPTS` / `EXB_LOCKOUT_MINUTES` | `5` / `15` | Sign-in lockout per user name |
| `EXB_2FA_ISSUER` | `EX Config Builder` | Name shown in the authenticator app |

## Backups

Everything worth keeping is `users.db` in the data volume. Back it up with
`sqlite3 users.db ".backup '/backup/exbuilder-users.db'"` (safe while running).
