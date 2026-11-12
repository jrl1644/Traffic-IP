# Traffic-IP

**Version 26.11.11-37** (versions are `YY.MM.DD-revision` and shown under the app name in the header; earlier releases used `MM.DD.YY-revision`)

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

Open **http://localhost:8187** (or `http://<server-ip>:8187` from another computer).

The first time, you'll be asked to **create the owner account**. The owner is always an Admin and can't be deleted or disabled.

Stop it with `docker compose down`. Your data stays in the `traffic-ip-data` volume.

### Without Compose

```bash
docker build -t traffic-ip .
docker run -d --name traffic-ip -p 8187:8187 \
  -v traffic-ip-data:/data --restart unless-stopped traffic-ip
```

### Without Docker

Node.js 22.5 or newer (it has SQLite built in): `node --disable-warning=ExperimentalWarning server.js` (data goes to `./data`).

---

## Settings (environment variables)

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `8187` | Port inside the container. |
| `DATA_DIR` | `/data` | Where the database and backups are kept. |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | Create the owner account at first start instead of in the browser. Only used when no accounts exist yet; remove them afterwards. |
| `ADMIN_NAME` | `Administrator` | Display name for that owner account. |
| `TRUST_PROXY` | `false` | Set to `true` only when the app is behind your own reverse proxy, so sign-in limits use each person's real address instead of the proxy's. Leave it off otherwise. |
| `COOKIE_SECURE` | `false` | Set to `true` when the app is reached over **HTTPS**. |
| `SESSION_DAYS` | `14` | How long a sign-in lasts. |
| `PING_CONCURRENCY` | `16` | How many devices the Ping check pings at the same time. |
| `CHANGELOG_DAYS` | `365` | How many days the change log keeps entries. |
| `TZ` | — | Time zone for log timestamps. |

---

## Phones and desktop

The app detects the device it runs on. iPhones and other phones (and any window narrower than about 760px) get a touch layout: a **☰ Menu** for the header actions, folding **Filters**, larger buttons, intersection cards with their actions underneath, and forms as full-screen sheets with the buttons always in reach. Desktops keep the full layout.

## Accounts, roles and privileges

Open **Admin** in the header (Admins only).

- **Accounts & roles:** create accounts with a temporary password, set each person's role, reset passwords, and disable or delete accounts. Disabling or deleting someone signs them out straight away.
- **Role privileges:** tick what **Technicians** and **Viewers** may do (add/edit/remove devices and intersections, manage the Device list and address pools). Admins can always do everything.
- **Settings → Backup & Restore:** download all data as one `.json` file, or restore a backup (replaces all data; type RESTORE to confirm). **Reset database** gives a clean start: it deletes all intersections, devices, address pools and the Device list, and clears the custom icon and settings (type RESET to confirm). Accounts and role privileges are kept. A copy of the deleted data is saved in `/data/backups/before-reset-….json`. User accounts and passwords aren't included and aren't changed. Before a restore, the server saves a copy of the replaced data in `/data/backups/before-restore-….json`. Backups from the claude.ai version of the app can be restored here too.
- **Settings → Custom icon:** upload your organization's logo or a photo (PNG, JPG, SVG or WebP). It's resized and cropped automatically to fill the top-left corner of the header, shown on the sign-in screen, and used as the app's icon for browser tabs, bookmarks and iPhone/Android **Add to Home Screen** (a built-in Traffic-IP icon is used until you upload one).

Everyone can use **Account** in the header to change their own password or sign out.

**Roles are enforced by the server.** Someone without permission can't make a change even by bypassing the screens. The server also refuses duplicate IP addresses, even when two people save at the same moment.

---

## Ping check

**Admin → Settings → Ping check** turns on reachability checks. The server pings every device's IP at the interval you choose, and each intersection bar shows a circle:

- 🟢 **Green:** all devices replied
- 🟡 **Yellow:** some didn't reply (hover to see which)
- 🔴 **Red:** none replied
- ⚪ **Grey:** the check is off, or the intersection has no devices

Results update live for everyone and aren't stored. **Check now** runs a check straight away.

The pings come from the server, so devices must be reachable from wherever the container runs. The image includes `ping`, and Docker normally allows it without extra permissions. If Settings says the server **isn't allowed to send pings**, either:

- add this to the service in `docker-compose.yml`:
  ```yaml
      sysctls:
        net.ipv4.ping_group_range: "0 2147483647"
  ```
- or, with Docker older than 20.10, add `cap_add: [NET_RAW]` and `user: root`.

Optional settings: `PING_CONCURRENCY` (default `16`) is how many devices are pinged at once.

## Data and backups

- Everything lives in a SQLite database, `/data/traffic-ip.sqlite` (in the `traffic-ip-data` volume). Each change is saved the moment it's made; a crash or power cut can't leave it half-written.
- Device IPs are indexed, so the duplicate-IP check stays instant even with hundreds of thousands of devices.
- **Upgrading from an older version** (which used `/data/db.json`): on first start the old file is imported automatically, including accounts and sign-ins, and kept as `/data/db.json.imported`.
- Each time the server starts, it saves a copy of the database to `/data/backups/` and keeps the last 20 copies.
- Admins can download or restore a full backup from **Admin → Settings → Backup & Restore**. Before a restore or a reset, the current data is saved to `/data/backups/before-restore-….json` or `before-reset-….json`.

Copy the backups off the server (keep at least one copy somewhere other than this machine):

```bash
docker cp traffic-ip:/data/backups ./traffic-ip-backups
```

Put a server copy back: stop the container, replace `/data/traffic-ip.sqlite` with the copy, and start it again.

```bash
docker compose down
docker run --rm -v traffic-ip_traffic-ip-data:/data -v "$PWD":/in alpine \
  sh -c 'rm -f /data/traffic-ip.sqlite-wal /data/traffic-ip.sqlite-shm && cp /in/db-YYYY-MM-DD....sqlite /data/traffic-ip.sqlite'
docker compose up -d
```

(The volume name may differ. `docker volume ls` shows it.)

## Change log

**Admin → Change log** lists every change: devices, intersections, address pools, the Device list, settings, restores and accounts (created, role changed, disabled, password reset, deleted). Each entry shows who made it, when, and what changed (for example *IP: 10.20.0.4 → 10.20.0.9*); open an entry to see the full before and after. Search by device, IP, street or username. Entries are kept for `CHANGELOG_DAYS` days (default 365). Only admins can see it. Uploaded icons aren't copied into the log.

---

## Security

- Passwords are stored as salted scrypt hashes. Sign-in tokens are random, kept in an HttpOnly cookie, and stored in the database only as hashes.
- Wrong-password attempts are limited (10 per username and 50 per address every 10 minutes). Sign-in takes the same time whether or not a username exists.
- Every change is recorded in the change log with who made it and when.
- Roles are checked by the server on every change, duplicate IPs are refused by the server, and requests that don't come from the app itself are rejected.
- Pages are sent with a strict Content-Security-Policy and other protective headers.
- **First start:** whoever opens the app first creates the owner account. Do that (or set `ADMIN_USERNAME`/`ADMIN_PASSWORD`) **before** making the app reachable by others.
- Use HTTPS (`COOKIE_SECURE=true` behind a reverse proxy) for anything beyond your local network.

## Using it over the internet / HTTPS

The container serves plain HTTP. For access beyond your local network, put it behind a reverse proxy that adds HTTPS (Caddy, nginx, Traefik, or your existing one) and set `COOKIE_SECURE=true`.

Example with Caddy (automatic certificates):

```
inventory.example.com {
    reverse_proxy localhost:8187
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

- **Custom device fields:** admins open **Add device** (or Edit) and click **⚙ Custom fields…** to add extra fields (text, number, date or dropdown, optionally required) to the Add/Edit device form. Each one can be shown as a column, printed and searched.
- **Print:** click **Print** on an intersection bar for a clean page with your icon and the intersection as its heading. Tick which intersection details and device columns to print; your choices are remembered.
- Street-sign fonts load from Google Fonts when the browser is online. Without internet access the app works the same, using the system font.
- **📍 Map** and **Pick on map** open Google Maps in the browser, which needs internet access.
- `build.py` regenerates `public/index.html` from the app source if you change it.
