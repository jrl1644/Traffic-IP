# Traffic-IP

**Version 11.11.26-2** (versions are `MM.DD.YY-revision` and shown next to the app name in the header)

Tracks IP-based devices at street intersections: searchable inventory, address pools with automatic IP assignment, a managed Device list, user accounts with roles, and live updates between everyone using it.

This version runs on its own server: no claude.ai account is needed. It has **no external dependencies**: only Node.js, and the data is kept in a single file on a Docker volume.

---

## Quick start

You need Docker (Docker Desktop on Windows/Mac, or Docker Engine on Linux).

The included `docker-compose.yml` builds the app **directly from this GitHub repo**, so on a server you only need that one file:

```bash
mkdir traffic-ip && cd traffic-ip
curl -O https://raw.githubusercontent.com/jrl1644/Traffic-IP/main/docker-compose.yml
docker compose up -d --build
```

(Or clone the whole repo and run `docker compose up -d --build` in it. It still builds from GitHub.)

Open **http://localhost:8080** (or `http://<server-ip>:8080` from another computer).

The first time, you'll be asked to **create the owner account**. The owner is always an Admin and can't be deleted or disabled.

Stop it with `docker compose down`. Your data stays in the `traffic-ip-data` volume.

### Without Compose

```bash
docker build -t traffic-ip .
docker run -d --name traffic-ip -p 8080:8080 \
  -v traffic-ip-data:/data --restart unless-stopped traffic-ip
```

### Without Docker

Node.js 20 or newer: `node server.js` (data goes to `./data`).

---

## Settings (environment variables)

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `8080` | Port inside the container. |
| `DATA_DIR` | `/data` | Where the database and backups are kept. |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | Create the owner account at first start instead of in the browser. Only used when no accounts exist yet; remove them afterwards. |
| `ADMIN_NAME` | `Administrator` | Display name for that owner account. |
| `COOKIE_SECURE` | `false` | Set to `true` when the app is reached over **HTTPS**. |
| `SESSION_DAYS` | `14` | How long a sign-in lasts. |
| `TZ` | — | Time zone for log timestamps. |

---

## Accounts, roles and privileges

Open **Admin** in the header (Admins only).

- **Accounts & roles:** create accounts with a temporary password, set each person's role, reset passwords, and disable or delete accounts. Disabling or deleting someone signs them out straight away.
- **Role privileges:** tick what **Technicians** and **Viewers** may do (add/edit/remove devices and intersections, manage the Device list and address pools, copy the CSV export). Admins can always do everything.
- **Access & sharing:** a summary of how access works, plus **Download backup**.

Everyone can use **Account** in the header to change their own password or sign out.

**Roles are enforced by the server.** Someone without permission can't make a change even by bypassing the screens. The server also refuses duplicate IP addresses, even when two people save at the same moment.

---

## Data and backups

- Everything lives in `/data/db.json` (in the `traffic-ip-data` volume). It's written safely: a crash can't leave a half-written file.
- Each time the server starts, it copies the database to `/data/backups/` and keeps the last 20 copies.
- Admins can download a full backup from **Admin → Access & sharing**.

Copy the backups off the server:

```bash
docker cp traffic-ip:/data/backups ./traffic-ip-backups
```

Restore a backup copy: stop the container, replace `/data/db.json` with the copy, and start it again.

```bash
docker compose down
docker run --rm -v traffic-ip_traffic-ip-data:/data -v "$PWD":/in alpine \
  cp /in/db-YYYY-MM-DD....json /data/db.json
docker compose up -d
```

(The volume name may differ. `docker volume ls` shows it.)

---

## Using it over the internet / HTTPS

The container serves plain HTTP. For access beyond your local network, put it behind a reverse proxy that adds HTTPS (Caddy, nginx, Traefik, or your existing one) and set `COOKIE_SECURE=true`.

Example with Caddy (automatic certificates):

```
inventory.example.com {
    reverse_proxy localhost:8080
}
```

Live updates use Server-Sent Events on `/api/events`. If your proxy buffers responses, turn buffering off for that path (nginx: `proxy_buffering off;`).

---

## Updating

```bash
docker compose up -d --build
```

This rebuilds from the latest `main` on GitHub. Your data in the volume is kept.

To run **local changes** instead (e.g. you edited the files), build from the folder: `docker build -t traffic-ip:latest . && docker compose up -d`, or change `context:` in `docker-compose.yml` to `.`.

To pin a specific version, change `#main` in `docker-compose.yml` to a tag or commit, e.g. `#ff3e500`.

## Notes

- Street-sign fonts load from Google Fonts when the browser is online. Without internet access the app works the same, using the system font.
- **📍 Map** and **Pick on map** open Google Maps in the browser, which needs internet access.
- `build.py` regenerates `public/index.html` from the app source if you change it.
