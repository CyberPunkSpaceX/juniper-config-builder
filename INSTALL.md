# Installing Multi-Vendor Switch Config Builder

A step-by-step guide, written for people who have never deployed a container
before. Copy the commands as they are, and swap anything in `<angle brackets>`
for your own value (without the brackets).

**Contents**

1. [What you need](#1-what-you-need)
2. [Install Docker](#2-install-docker)
3. [Get access to the image](#3-get-access-to-the-image)
4. [Option A: one server with Docker Compose](#4-option-a-one-server-with-docker-compose) (easiest)
5. [Option B: Docker Swarm](#5-option-b-docker-swarm) (what a cluster uses)
6. [First sign-in](#6-first-sign-in)
7. [HTTPS with a reverse proxy](#7-https-with-a-reverse-proxy)
8. [Upgrading](#8-upgrading)
9. [Backups and restore](#9-backups-and-restore)
10. [All settings](#10-all-settings)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. What you need

| | |
|---|---|
| A Linux server or VM | Ubuntu 22.04/24.04 or Debian 12 are what this guide uses. 1 CPU, 1 GB RAM and 5 GB disk are plenty. Intel/AMD (amd64) or ARM (arm64) both work. |
| Docker Engine | Version 24 or newer, installed in step 2. |
| A user with `sudo` | You'll run the commands as that user. |
| Free ports | **8088/tcp** for the web page. **514/udp+tcp** only if you want the built-in syslog server. |
| Optional | A domain name and a reverse proxy for HTTPS (step 7), an SMTP account for email alerts. |

Everything the app stores (users, clients, projects, config backups, logs) lives
in **one data folder** (`/data` inside the container, kept in a Docker volume).
Back that up and you've backed up everything.

## 2. Install Docker

Skip this if `docker --version` already prints a version.

```bash
# Docker's own install script (Ubuntu, Debian, Fedora, ...)
curl -fsSL https://get.docker.com | sudo sh

# Let your user run docker without sudo, then log out and back in
sudo usermod -aG docker $USER
```

Check it worked:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

If you'd rather install from packages by hand, follow
<https://docs.docker.com/engine/install/>.

## 3. Get access to the image

The app ships as a ready-made image:

```
ghcr.io/cyberpunkspacex/switch-config-builder:latest
```

It's built automatically on every change to `main` (for amd64 and arm64).
While the GitHub repository is private, the image is private too, so each
server has to sign in to GitHub's registry once:

1. On GitHub: your picture (top right) > **Settings** > **Developer settings** >
   **Personal access tokens** > **Tokens (classic)** > **Generate new token (classic)**.
2. Give it a name, tick only **`read:packages`**, and generate it. Copy the
   token now; GitHub never shows it again.
3. On the server:

   ```bash
   docker login ghcr.io -u <your-github-username>
   # paste the token when it asks for a password
   ```

4. Test it: `docker pull ghcr.io/cyberpunkspacex/switch-config-builder:latest`

If the repository is public, skip this step.

Prefer to build it yourself? `git clone` the repository and run
`docker build -t switch-config-builder .` in it, then use
`switch-config-builder` as the image name in the files below.

## 4. Option A: one server with Docker Compose

The easiest way. One server, one command.

1. Make a folder and fetch the compose file:

   ```bash
   mkdir -p ~/switchbuilder && cd ~/switchbuilder
   curl -fsSLO https://raw.githubusercontent.com/CyberPunkSpaceX/switch-config-builder/main/deploy/docker-compose.yml
   ```

   (Private repository? Download `deploy/docker-compose.yml` from the GitHub
   page instead and copy it to the server, or `git clone` the repository.)

2. Optional but recommended: make a master key. It encrypts the SSH keys you
   give the app for your switches. Without it the app makes one in its data
   folder by itself, which works, but then the key sits right next to the data
   it protects (and in every backup of it).

   ```bash
   head -c 32 /dev/urandom | base64 > master_key
   sudo chown 10001 master_key && sudo chmod 600 master_key   # the app runs as user 10001
   ```

   Then open `docker-compose.yml` and remove the `#` in front of the lines
   marked `master key`. **Keep a copy of this file somewhere safe.** Lose it and
   the stored SSH keys can't be read any more (you'd have to enter them again).

3. Start it:

   ```bash
   docker compose up -d
   ```

4. Check that it's running:

   ```bash
   docker compose ps          # both services "running" / "healthy"
   docker compose logs web    # look for "created 'admin'"
   ```

5. Open `http://<server-ip>:8088` and carry on with [First sign-in](#6-first-sign-in).

The compose file runs two services from the same image:

* **web**: the web page on port 8088.
* **jobs**: nightly config backups, alerts and the built-in syslog server
  (port 514). If you don't need syslog, delete the `ports:` part of `jobs`.

## 5. Option B: Docker Swarm

Use this when you already run a swarm (or want Portainer to manage it). The
data volume is a normal local volume, so both services are **pinned to one
node**, the one that keeps the data.

1. No swarm yet? On the first server:

   ```bash
   docker swarm init --advertise-addr <this-server-ip>
   ```

   It prints a `docker swarm join ...` command; run that on any other servers
   you want to add. A swarm of one node is fine.

2. Find the name of the node that will keep the data:

   ```bash
   docker node ls      # the HOSTNAME column, e.g. docker-01
   ```

3. Get the stack file onto a manager node (same as step 4.1, but the file is
   `deploy/switchbuilder-stack.yml`).

4. Recommended: create the master key as a Docker secret (see step 4.2 for why).
   Save a copy first, because Docker never shows a secret again:

   ```bash
   head -c 32 /dev/urandom | base64 > master_key   # keep this file somewhere safe
   docker secret create switchbuilder_master_key master_key
   rm master_key                                   # once it's stored safely elsewhere
   ```

   Then in `switchbuilder-stack.yml`, remove the `#` in front of every
   `EXB_MASTER_KEY_FILE` line and every `secrets:` block (there are three:
   under `web`, under `jobs`, and at the very bottom).

5. Deploy:

   ```bash
   EXB_NODE=<node-hostname> docker stack deploy \
     -c switchbuilder-stack.yml --with-registry-auth switchbuilder
   ```

   `--with-registry-auth` passes your `docker login` from step 3 to the nodes.
   Other settings go in front the same way, for example
   `EXB_NODE=docker-01 EXB_PUBLIC_URL=https://switchbuilder.example.com docker stack deploy ...`.
   Put them all in a small script so the next deploy uses the same ones.

   **In Portainer instead:** Stacks > Add stack > Web editor, paste the stack
   file, add `EXB_NODE` (and any other settings) under *Environment variables*,
   and click Deploy. Portainer needs registry access to `ghcr.io` (Registries >
   Add registry > Custom, with your username and token).

6. Check:

   ```bash
   docker stack services switchbuilder     # web and jobs show 1/1
   docker service logs switchbuilder_web
   ```

7. Open `http://<any-node-ip>:8088` (the swarm forwards it from every node).
   Switches send syslog to **the node in `EXB_NODE`**, port 514, because that
   port is published only on that node, so the app sees each switch's real
   address.

## 6. First sign-in

1. Open the page and sign in as **`admin`** / **`admin`**.
2. You're asked for a new password straight away. Pick a good one; this
   account is a Super Admin.
3. You're asked to set up an authenticator app (Google Authenticator, Microsoft
   Authenticator, 1Password, Bitwarden, ...) because admins need two-factor
   sign-in. Scan the QR code and type the 6-digit code.
4. Make yourself a normal account for daily work: **Users** > add user. Give
   other people their own accounts rather than sharing `admin`.
5. Add your first client, pick a switch brand and build. The **Help** page in
   the app explains each screen.

Want a different first admin than `admin`/`admin`? Set `EXB_USERNAME` and
`EXB_PASSWORD_FILE` (or `EXB_PASSWORD`) **before the very first start**. They're
only used while the database is empty.

Forgot the admin password? Any other Super Admin can reset it on the Users
page. If there's no other one, stop the app, restore a backup from before, or
start over with an empty volume.

## 7. HTTPS with a reverse proxy

Don't put the plain `:8088` page on the internet: passwords and switch secrets
travel over it. Put a reverse proxy with a TLS certificate in front.

**Nginx Proxy Manager** (or Traefik, Caddy, plain Nginx):

1. Add a proxy host for your name, e.g. `switchbuilder.example.com`.
2. Forward to `http://<docker-server-ip>:8088`.
3. On the SSL tab, request a Let's Encrypt certificate and turn on *Force SSL*.
4. In *Advanced*, raise the timeout: some actions (bulk builds, SSH fetches from
   many switches) take a few minutes:

   ```nginx
   proxy_read_timeout 300s;
   ```

Plain Nginx, for reference:

```nginx
server {
    listen 443 ssl;
    server_name switchbuilder.example.com;
    ssl_certificate     /etc/letsencrypt/live/switchbuilder.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/switchbuilder.example.com/privkey.pem;
    client_max_body_size 30m;

    location / {
        proxy_pass http://<docker-server-ip>:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

Then tell the app it lives behind HTTPS and redeploy (Compose: edit the file,
`docker compose up -d`; Swarm: add them in front of `docker stack deploy`):

| Setting | Value |
|---|---|
| `EXB_SECURE_COOKIES` | `true`: the sign-in cookie is only sent over HTTPS. After this, signing in over plain `http://...:8088` no longer works. That's the point. |
| `EXB_PUBLIC_URL` | `https://switchbuilder.example.com`: used for links in alert emails and company sign-in (OIDC/SAML). |
| `EXB_TRUSTED_PROXIES` | `1` for one proxy in front (the default). The lockout after wrong passwords uses the real visitor address from `X-Forwarded-For`. |

Once the proxy works, firewall port 8088 so only the proxy can reach it.

## 8. Upgrading

Back up first (step 9). The database upgrades itself when the new version
starts, and there's no automatic way back down.

**Compose:**

```bash
cd ~/switchbuilder
docker compose pull
docker compose up -d
docker image prune -f      # remove the old image
```

**Swarm:** run the same deploy command as in step 5 again, with the same
settings. If the service doesn't restart (Swarm sometimes keeps the old image
because `:latest` looks unchanged), force it:

```bash
docker service update --with-registry-auth --force \
  --image ghcr.io/cyberpunkspacex/switch-config-builder:latest switchbuilder_web
docker service update --with-registry-auth --force \
  --image ghcr.io/cyberpunkspacex/switch-config-builder:latest switchbuilder_jobs
```

To roll back, deploy the previous image by its tag (every build is also tagged
`sha-<commit>`, see the package page on GitHub) and restore the backup you
took before the upgrade.

## 9. Backups and restore

### What to keep

| File (in the data volume) | What it is |
|---|---|
| `users.db` | Everything: users, clients, projects, maps, config backups, logs, audit log. |
| `master_key` | Only if you did **not** use a master key file/secret. Without it, stored SSH keys can't be decrypted. |
| `secret_key` | Signs sign-in sessions. Losing it just signs everyone out. |

Plus, outside the volume: your copy of the master key, and your compose/stack
file with the settings you used.

### Back up (safe while it runs)

The image has Python's SQLite built in, which can copy a live database safely.
This writes a dated copy into the volume and then copies it out:

**Compose:**

```bash
cd ~/switchbuilder
STAMP=$(date +%Y%m%d-%H%M%S)
docker compose exec -T web python -c \
  "import sqlite3; sqlite3.connect('/data/users.db').backup(sqlite3.connect('/data/users.db.$STAMP.bak'))"
mkdir -p ~/switchbuilder-backups
docker compose cp web:/data/users.db.$STAMP.bak ~/switchbuilder-backups/
docker compose cp web:/data/secret_key ~/switchbuilder-backups/secret_key
docker compose cp web:/data/master_key ~/switchbuilder-backups/master_key 2>/dev/null || true
docker compose exec -T web rm /data/users.db.$STAMP.bak
```

**Swarm** (run on the node in `EXB_NODE`):

```bash
C=$(docker ps -q -f name=switchbuilder_web)
STAMP=$(date +%Y%m%d-%H%M%S)
docker exec $C python -c \
  "import sqlite3; sqlite3.connect('/data/users.db').backup(sqlite3.connect('/data/users.db.$STAMP.bak'))"
mkdir -p ~/switchbuilder-backups
docker cp $C:/data/users.db.$STAMP.bak ~/switchbuilder-backups/
docker cp $C:/data/secret_key ~/switchbuilder-backups/
docker cp $C:/data/master_key ~/switchbuilder-backups/ 2>/dev/null || true
docker exec $C rm /data/users.db.$STAMP.bak
```

Run it every night with cron (`crontab -e`, then a line like
`15 4 * * * /home/<you>/backup-switchbuilder.sh`) and copy
`~/switchbuilder-backups` to another machine or a NAS. A backup on the same disk
dies with the same disk.

Separately, inside the app, each client has **Back up now** (one JSON file with
that client's projects, maps and config backups) and the nightly switch config
backups. Those are handy for moving one client, but they don't replace backing
up `users.db`.

### Restore

1. Stop the app:
   * Compose: `docker compose stop`
   * Swarm: `docker service scale switchbuilder_web=0 switchbuilder_jobs=0`
2. Copy the backup over the database. The volume's folder on the host is shown
   by `docker volume inspect`. With the names used in this guide the volume is
   `switchbuilder_switchbuilder_data` (Compose folder or stack name, then the
   volume name); `docker volume ls` lists them all. On Swarm, do this on the
   node in `EXB_NODE`.

   ```bash
   V=$(docker volume inspect switchbuilder_switchbuilder_data --format '{{ .Mountpoint }}')
   sudo cp ~/switchbuilder-backups/users.db.<stamp>.bak "$V/users.db"
   sudo rm -f "$V/users.db-wal" "$V/users.db-shm"
   sudo chown 10001 "$V/users.db"          # the app runs as user 10001
   ```

   Moving to a new server? Copy `master_key` and `secret_key` back too (or
   create the same master key secret).
3. Start it again: `docker compose start`, or
   `docker service scale switchbuilder_web=1 switchbuilder_jobs=1`.

## 10. All settings

Set these in the compose file (`environment:`) or in front of the
`docker stack deploy` command. Only `EXB_NODE` (Swarm) is required.

| Variable | Default | Meaning |
|---|---|---|
| `EXB_NODE` | | Swarm only: hostname of the node that keeps the data volume |
| `EXB_PORT` | `8088` | Swarm only: port for the web page |
| `EXB_DATA_DIR` | `/data` | Where the database and keys live (inside the container) |
| `EXB_USERNAME` / `EXB_PASSWORD` / `EXB_PASSWORD_FILE` | | First admin on an empty database (otherwise admin / admin with a forced change) |
| `EXB_SECURE_COOKIES` | `false` | Send the session cookie over HTTPS only |
| `EXB_PUBLIC_URL` | | The address people use, e.g. `https://switchbuilder.example.com` |
| `EXB_TRUSTED_PROXIES` | `1` | How many proxies in front add to `X-Forwarded-For` (Nginx Proxy Manager = 1). Only believed when the request comes from a private address |
| `EXB_REQUIRE_2FA` | `false` | Everyone must set up an authenticator app |
| `EXB_REQUIRE_2FA_ADMINS` | `true` | Server admins must set up an authenticator app |
| `EXB_2FA_ISSUER` | `Multi-Vendor Switch Config Builder` | Name shown in the authenticator app |
| `EXB_SESSION_HOURS` | `12` | How long a sign-in lasts |
| `EXB_LOCKOUT_ATTEMPTS` / `EXB_LOCKOUT_MINUTES` | `5` / `15` | Wrong passwords for one user name from one address before that address is blocked, and for how long |
| `EXB_LOCKOUT_IP_ATTEMPTS` | `20` | Wrong passwords for any user names from one address before that address is blocked |
| `EXB_MASTER_KEY_FILE` | `/data/master_key` | File with the key that encrypts stored SSH keys |
| `EXB_SSH_ALLOW` | private ranges | Networks any client may SSH to (comma separated) |
| `EXB_SSH_DISABLE` | `false` | `true` turns SSH config fetch off for everyone |
| `EXB_SSH_KEY_FILE` / `EXB_SSH_KEY_USER` | | A server-wide SSH key and user, for clients without their own |
| `EXB_SSH_TIMEOUT` / `EXB_SSH_RATE` | `20` / `10` | SSH timeout in seconds, and fetches a minute per user |
| `EXB_PUSH_DISABLE` | `false` | `true` turns pushing configs to switches off |
| `EXB_SMTP_HOST` / `EXB_SMTP_PORT` / `EXB_SMTP_TLS` | / `587` / `starttls` | Mail server for alerts (`EXB_SMTP_TLS`: `starttls`, `ssl` or `none`) |
| `EXB_SMTP_USER` / `EXB_SMTP_PASSWORD_FILE` / `EXB_SMTP_FROM` | | Mail account and sender address |
| `EXB_SYSLOG_ADDRESS` | | The address switches should send syslog to, shown on the log settings page |
| `EXB_SYSLOG_PUBLISHED` | `514` | Swarm only: port the syslog server is published on |
| `EXB_SYSLOG_PORT` | `5514` | Port inside the jobs container; `0` turns the syslog server off |
| `EXB_SYSLOG_RATE` / `EXB_SYSLOG_MAX_ROWS` | `200` / `2000000` | Messages a second per sender, and messages kept per client |
| `EXB_AUDIT_DAYS` | `365` | Days the audit log keeps |

Passwords belong in files (`..._FILE` settings with a Docker secret or a
`chmod 600` file), not straight in the compose file.

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `denied` or `unauthorized` when pulling | Do step 3 (`docker login ghcr.io`), and add `--with-registry-auth` on Swarm. |
| Swarm service stuck at `0/1`, "no suitable node" | `EXB_NODE` doesn't match a hostname in `docker node ls`. |
| Sign-in page just reloads, no error | `EXB_SECURE_COOKIES=true` but you opened plain `http://`. Use the HTTPS address. |
| "Too many attempts" | Wait `EXB_LOCKOUT_MINUTES` (15 by default). The block is per address, so signing in from another machine works. |
| Every visitor gets locked out together | The proxy's address is counted, not the visitor's: check `EXB_TRUSTED_PROXIES` and that the proxy sends `X-Forwarded-For`. |
| Port 8088 or 514 "already in use" | Change the left-hand number in the compose file (`"8089:8080"`), or `EXB_PORT` / `EXB_SYSLOG_PUBLISHED` on Swarm. |
| `permission denied` on `/data` | The app runs as user 10001. `sudo chown -R 10001 <volume folder>`. |
| Long actions end with "502/504" | Raise the proxy timeout to 300 seconds (step 7). |
| Upgrade did nothing | Swarm kept the old image: use the `--force` commands in step 8. |

Still stuck? Look at the logs (`docker compose logs` or
`docker service logs switchbuilder_web`); errors are written there.
