// Traffic-IP — standalone server
const VERSION = "26.11.11-15";   // YY.MM.DD-revision — keep in step with APP_VERSION in app-source.html
// No external dependencies: Node.js 20+ built-ins only.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");
const { execFile } = require("child_process");

const PORT = parseInt(process.env.PORT || "8187", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE || "");
const TRUST_PROXY = /^(1|true|yes)$/i.test(process.env.TRUST_PROXY || "");   // set when behind a reverse proxy, so login limits use the real client address
const SESSION_DAYS = parseFloat(process.env.SESSION_DAYS || "14");
const DB_FILE = path.join(DATA_DIR, "db.json");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const MAX_BODY = 512 * 1024;

/* ------------------------------------------------------------------ storage */
fs.mkdirSync(BACKUP_DIR, { recursive: true });
let state = { collections: {}, users: {}, sessions: {} };
if (fs.existsSync(DB_FILE)) {
  state = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  state.collections ||= {}; state.users ||= {}; state.sessions ||= {};
  // keep a copy of the database each time the server starts (last 20)
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  fs.copyFileSync(DB_FILE, path.join(BACKUP_DIR, `db-${stamp}.json`));
  const old = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith("db-")).sort();
  old.slice(0, Math.max(0, old.length - 20)).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
}
let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DB_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, DB_FILE);                    // atomic replace
  }, 150);
}
function flushSync() {
  clearTimeout(saveTimer);
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, DB_FILE);
}
process.on("SIGTERM", () => { flushSync(); process.exit(0); });
process.on("SIGINT", () => { flushSync(); process.exit(0); });

const RESERVED = new Set(["__proto__", "constructor", "prototype"]);
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const coll = name => { if (RESERVED.has(name)) throw new Error("reserved"); if (!own(state.collections, name)) state.collections[name] = {}; return state.collections[name]; };
const peek = name => (!RESERVED.has(name) && own(state.collections, name)) ? state.collections[name] : {};   // read without creating

/* ------------------------------------------------------------------ roles */
const PERMS = ["devices.add","devices.edit","devices.remove","inters.add","inters.edit","inters.remove","devlist.manage","pools.manage","export.csv"];
const DEFAULT_ROLES = {
  admin: Object.fromEntries(PERMS.map(p => [p, true])),
  technician: { "devices.add":true,"devices.edit":true,"devices.remove":false,"inters.add":true,"inters.edit":true,"inters.remove":false,"devlist.manage":false,"pools.manage":false,"export.csv":true },
  viewer: { "export.csv": true },
};
const ROLES = ["admin", "technician", "viewer"];
function rolePerms(role) {
  if (role === "admin") return DEFAULT_ROLES.admin;
  const cfg = peek("admin").config || {};
  return { ...DEFAULT_ROLES[role] || {}, ...(cfg.roles?.[role]?.perms || {}) };
}
function userRole(u) { return u.owner ? "admin" : (ROLES.includes(u.role) ? u.role : "viewer"); }
function can(u, perm) { return userRole(u) === "admin" || !!rolePerms(userRole(u))[perm]; }
function canWriteAny(u) { const r = userRole(u); return r === "admin" || PERMS.some(p => p !== "export.csv" && rolePerms(r)[p]); }

/* ------------------------------------------------------------------ passwords & sessions */
function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(pw), salt, 64).toString("hex");
  return { salt, hash };
}
function checkPassword(u, pw) {
  const { hash } = hashPassword(pw, u.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(u.hash, "hex"));
}
function validPassword(pw) { return typeof pw === "string" && pw.length >= 8; }
const publicUser = u => ({ id: u.id, username: u.username, name: u.name || "", email: u.email || "", role: userRole(u), owner: !!u.owner, disabled: !!u.disabled, created: u.created, lastLogin: u.lastLogin || null });
function findUser(username) { const n = String(username || "").trim().toLowerCase(); return Object.values(state.users).find(u => u.username.toLowerCase() === n); }
function checkLogin(username, pw) { const u = findUser(username); const ok = checkPassword(u || DUMMY, String(pw || "")); return u && ok ? u : null; }
const tokenKey = t => crypto.createHash("sha256").update(t).digest("hex");   // the database never holds a usable sign-in token
function newSession(u) {
  const token = crypto.randomBytes(32).toString("hex");
  state.sessions[tokenKey(token)] = { v: 2, userId: u.id, expires: Date.now() + SESSION_DAYS * 864e5 };
  u.lastLogin = new Date().toISOString(); save();
  return token;
}
function sessionUser(req) {
  const m = /(?:^|;\s*)iid_session=([a-f0-9]{64})/.exec(req.headers.cookie || "");
  if (!m) return null;
  const key = tokenKey(m[1]);
  const s = own(state.sessions, key) ? state.sessions[key] : null;
  if (!s || s.expires < Date.now()) { if (s) { delete state.sessions[key]; save(); } return null; }
  const u = own(state.users, s.userId) ? state.users[s.userId] : null;
  if (!u || u.disabled) return null;
  return Object.assign(u, { _token: key });
}
function cookie(token, maxAge) {
  return `iid_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${COOKIE_SECURE ? "; Secure" : ""}`;
}
setInterval(() => { const now = Date.now(); let n = 0; for (const [k, s] of Object.entries(state.sessions)) if (s.expires < now) { delete state.sessions[k]; n++; } if (n) save(); }, 3600e3);
// sessions from before tokens were hashed can't be matched any more: drop them
for (const k of Object.keys(state.sessions)) if (state.sessions[k]?.v !== 2) delete state.sessions[k];

// login throttle: 10 failures per 10 minutes per IP+username, and 50 per IP across all usernames
const fails = new Map();
function throttled(key, max = 10) { const f = fails.get(key); return f && f.n >= max && Date.now() - f.t < 600e3; }
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (now - f.t > 600e3) fails.delete(k); }, 600e3);
const clientIp = req => (TRUST_PROXY && String(req.headers["x-forwarded-for"] || "").split(",")[0].trim()) || req.socket.remoteAddress || "";
// equal work whether or not the username exists, so response time doesn't reveal which usernames are real
const DUMMY = hashPassword(crypto.randomBytes(16).toString("hex"));
function failed(key) { const f = fails.get(key) || { n: 0, t: Date.now() }; if (Date.now() - f.t > 600e3) { f.n = 0; f.t = Date.now(); } f.n++; fails.set(key, f); }

// first admin from environment, if provided and no users exist
if (!Object.keys(state.users).length && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  const id = "u_" + crypto.randomBytes(8).toString("hex");
  state.users[id] = { id, username: process.env.ADMIN_USERNAME.trim(), name: process.env.ADMIN_NAME || "Administrator", owner: true, role: "admin", created: new Date().toISOString(), ...hashPassword(process.env.ADMIN_PASSWORD) };
  flushSync();
  console.log(`Created owner account "${process.env.ADMIN_USERNAME}" from environment.`);
}

const leases = new Map();   // in memory only

/* ------------------------------------------------------------------ ping checks
   Admins turn this on under Settings. The server pings every device IP with the system
   "ping" command (never through a shell; the address is validated first) and tells every
   open page the results. Nothing is stored: results live in memory. */
const PING_BIN = process.env.PING_BIN || "ping";
const PING_CONCURRENCY = Math.max(1, Math.min(64, parseInt(process.env.PING_CONCURRENCY || "16", 10)));
const ping = { results: {}, lastRun: null, running: false, available: null, error: "", timer: null, manualAt: 0 };
function pingSettings() {
  const st = peek("admin").settings?.ping || {};
  return {
    enabled: !!st.enabled,
    intervalSec: Math.min(3600, Math.max(30, parseInt(st.intervalSec, 10) || 60)),
    timeoutSec: Math.min(10, Math.max(1, parseInt(st.timeoutSec, 10) || 1)),
  };
}
function pingOne(ip, timeoutSec) {
  return new Promise(resolve => {
    if (!net.isIP(ip)) return resolve({ ok: false, error: "not an IP address" });
    const args = ["-n", "-c", "1", "-W", String(timeoutSec), ip];
    execFile(PING_BIN, args, { timeout: (timeoutSec + 2) * 1000, windowsHide: true }, (e, out, errOut) => {
      const text = String(out || "") + String(errOut || "");
      const m = text.match(/time[=<]\s*([\d.]+)\s*ms/i);
      if (!e) return resolve({ ok: true, rttMs: m ? parseFloat(m[1]) : null });
      if (e.code === "ENOENT") return resolve({ ok: false, fatal: "The ping command isn't installed on this server." });
      if (/permission|not permitted|socket: Operation/i.test(text)) return resolve({ ok: false, fatal: "This server isn't allowed to send pings. " + text.trim().split("\n").pop() });
      resolve({ ok: false });
    });
  });
}
function pingPayload() {
  const st = pingSettings();
  return { type: "ping", enabled: st.enabled, intervalSec: st.intervalSec, timeoutSec: st.timeoutSec, available: ping.available, error: ping.error, running: ping.running, lastRun: ping.lastRun, results: ping.results };
}
async function runPings() {
  if (ping.running) return;
  const st = pingSettings();
  const ips = [...new Set(Object.values(peek("devices")).map(d => String(d.ip || "").trim()).filter(ip => net.isIP(ip)))];
  ping.running = true; broadcast({ ...pingPayload() });
  const results = {}; let i = 0, fatal = "";
  async function worker() { while (i < ips.length && !fatal) { const ip = ips[i++]; const r = await pingOne(ip, st.timeoutSec); if (r.fatal) { fatal = r.fatal; break; } results[ip] = { ok: r.ok, rttMs: r.rttMs ?? null, at: Date.now() }; } }
  await Promise.all(Array.from({ length: Math.min(PING_CONCURRENCY, ips.length || 1) }, worker));
  ping.running = false;
  if (fatal) { ping.available = false; ping.error = fatal; ping.results = {}; console.warn("Ping checks unavailable: " + fatal); }
  else { ping.available = true; ping.error = ""; ping.results = results; ping.lastRun = new Date().toISOString(); }
  broadcast(pingPayload());
}
function schedulePings(delayMs) {
  clearTimeout(ping.timer);
  const st = pingSettings();
  if (!st.enabled) { if (Object.keys(ping.results).length || ping.lastRun) { ping.results = {}; ping.lastRun = null; broadcast(pingPayload()); } return; }
  ping.timer = setTimeout(async () => { await runPings(); schedulePings(pingSettings().intervalSec * 1000); }, delayMs ?? 0);
}

/* ------------------------------------------------------------------ live updates (Server-Sent Events) */
const clients = new Set();
function broadcast(evt) {
  const msg = `data: ${JSON.stringify(evt)}\n\n`;
  for (const c of clients) { try { c.res.write(msg); } catch {} }
}
setInterval(() => { for (const c of clients) { try { c.res.write(": ping\n\n"); } catch {} } }, 25000);
// sign out live streams of a user who was disabled/deleted or changed role
function kickUser(userId) { for (const c of clients) if (c.userId === userId) { try { c.res.write(`data: ${JSON.stringify({ type: "reload" })}\n\n`); } catch {} } }

/* ------------------------------------------------------------------ write rules (enforced here, not just in the browser) */
const normStreet = s => String(s || "").replace(/"/g, "").replace(/\s+/g, " ").trim().toLowerCase();
function writeAllowed(u, c, id, kind /* create|update|delete */) {
  const map = {
    devices: { create: "devices.add", update: "devices.edit", delete: "devices.remove" },
    intersections: { create: "inters.add", update: "inters.edit", delete: "inters.remove" },
    pools: "pools.manage", deviceOptions: "devlist.manage",
  };
  if (c === "admin" || c === "members") return userRole(u) === "admin";
  if (c === "locks") return canWriteAny(u);
  const m = map[c];
  if (!m) return userRole(u) === "admin";
  if (typeof m === "string") return can(u, m);
  if (can(u, m[kind])) return true;
  // renaming an intersection replaces its record: allow removing the old record
  // with "edit" rights once no device still points at it
  if (c === "intersections" && kind === "delete" && can(u, "inters.edit")) {
    const doc = own(peek("intersections"), id) ? peek("intersections")[id] : null; if (!doc) return true;
    const a = normStreet(doc.street1), b = normStreet(doc.street2);
    return !Object.values(peek("devices")).some(d => { const x = normStreet(d.street1), y = normStreet(d.street2); return (x === a && y === b) || (x === b && y === a); });
  }
  return false;
}
function validate(c, id, data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return "Body must be an object.";
  if (c === "devices") {
    const ip = String(data.ip || "").trim();
    if (!ip) return "A device needs an IP address.";
    const taken = Object.entries(peek("devices")).find(([k, d]) => k !== id && String(d.ip).trim() === ip);
    if (taken) return { conflict: `IP ${ip} is already used by “${taken[1].name}”. Duplicate IPs aren't allowed.` };
  }
  return null;
}
const SEG_RE = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
const SEG = { test: v => SEG_RE.test(v) && !RESERVED.has(v) };

/* ------------------------------------------------------------------ http helpers */
function send(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers });
  res.end(body);
}
const err = (res, code, errCode, message) => send(res, code, { error: { code: errCode, message } });
function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", ch => { size += ch.length; if (size > limit) { reject(new Error("too large")); req.destroy(); } else chunks.push(ch); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "SAMEORIGIN",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  // only this server's own code runs; fonts from Google; images only from the page itself
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'",
};
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json" };
function serveStatic(req, res, urlPath) {
  let p = urlPath === "/" ? "/index.html" : urlPath;
  let decoded; try { decoded = decodeURIComponent(p); } catch { res.writeHead(400); return res.end("Bad request"); }
  const file = path.resolve(PUBLIC_DIR, "." + decoded);
  if (!file.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); return res.end("Not found"); }
  res.writeHead(200, {
    "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
    "Cache-Control": "no-cache",
    ...SECURITY_HEADERS,
  });
  fs.createReadStream(file).pipe(res);
}

/* ------------------------------------------------------------------ app icon (tabs, bookmarks, home screen)
   The custom icon's square version (made in the browser at upload) if there is one, otherwise the built-in icon. */
const ICON_PATHS = new Set(["/favicon.ico", "/favicon.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/icon-192.png", "/icon-512.png"]);
const DEFAULT_ICON = fs.readFileSync(path.join(PUBLIC_DIR, "default-icon.png"));
function currentIcon() {
  const b = peek("admin").branding || {};
  const m = typeof b.icon === "string" && b.icon.match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
  return m ? { type: m[1], body: Buffer.from(m[2], "base64"), tag: String(b.updated || "") } : { type: "image/png", body: DEFAULT_ICON, tag: "default" };
}
function serveIcon(req, res) {
  const ic = currentIcon();
  const etag = '"' + crypto.createHash("sha1").update(ic.body).digest("hex").slice(0, 16) + '"';
  if (req.headers["if-none-match"] === etag) { res.writeHead(304, { ETag: etag }); return res.end(); }
  res.writeHead(200, { "Content-Type": ic.type, "Content-Length": ic.body.length, "Cache-Control": "no-cache", ETag: etag, "X-Content-Type-Options": "nosniff" });
  res.end(ic.body);
}
function serveManifest(req, res) {
  const v = encodeURIComponent(currentIcon().tag), type = currentIcon().type;
  const body = JSON.stringify({
    name: "Traffic-IP", short_name: "Traffic-IP", start_url: "/", scope: "/", display: "standalone",
    background_color: "#f4f5f2", theme_color: "#1f6f4a",
    icons: [{ src: `/icon-192.png?v=${v}`, sizes: "192x192", type, purpose: "any" }, { src: `/icon-512.png?v=${v}`, sizes: "512x512", type, purpose: "any" }],
  });
  res.writeHead(200, { "Content-Type": "application/manifest+json", "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff" });
  res.end(body);
}

/* ------------------------------------------------------------------ routes */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  try {
    if (ICON_PATHS.has(p)) return serveIcon(req, res);
    if (p === "/manifest.webmanifest") return serveManifest(req, res);
    if (!p.startsWith("/api/")) return serveStatic(req, res, p);
    if (p === "/api/health") return send(res, 200, { ok: true, version: VERSION });
    // the logo is public so the sign-in screen can show it (nothing else is readable before signing in)
    if (p === "/api/branding" && req.method === "GET") {
      const logo = peek("admin").branding?.logo;
      return send(res, 200, { logo: typeof logo === "string" && logo.startsWith("data:image/") ? logo : "" });
    }

    // all state-changing API calls must come from the app itself (blocks cross-site form posts)
    if (req.method !== "GET" && req.headers["x-requested-with"] !== "iid") return err(res, 403, "forbidden", "Bad request origin.");

    /* --- session --- */
    if (p === "/api/session" && req.method === "GET") {
      const u = sessionUser(req);
      return send(res, 200, { needsSetup: !Object.keys(state.users).length, user: u ? { ...publicUser(u), perms: rolePerms(userRole(u)), canWrite: canWriteAny(u) } : null });
    }
    if (p === "/api/setup" && req.method === "POST") {
      if (Object.keys(state.users).length) return err(res, 409, "conflict", "Setup is already done.");
      const b = await readBody(req);
      if (!String(b.username || "").trim()) return err(res, 400, "invalid_argument", "Choose a username.");
      if (!validPassword(b.password)) return err(res, 400, "invalid_argument", "Passwords need at least 8 characters.");
      const id = "u_" + crypto.randomBytes(8).toString("hex");
      const u = state.users[id] = { id, username: String(b.username).trim(), name: String(b.name || "").trim(), email: String(b.email || "").trim(), owner: true, role: "admin", created: new Date().toISOString(), ...hashPassword(b.password) };
      const t = newSession(u); flushSync();
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie(t, SESSION_DAYS * 86400) });
    }
    if (p === "/api/login" && req.method === "POST") {
      const b = await readBody(req);
      const ip = clientIp(req), key = ip + "|" + String(b.username || "").toLowerCase();
      if (throttled(key) || throttled("ip|" + ip, 50)) return err(res, 429, "resource_exhausted", "Too many attempts. Try again in 10 minutes.");
      const u = checkLogin(b.username, b.password);
      if (!u) { failed(key); failed("ip|" + ip); return err(res, 401, "unauthenticated", "Wrong username or password."); }
      if (u.disabled) return err(res, 403, "forbidden", "This account is disabled. Ask an admin.");
      fails.delete(key);
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie(newSession(u), SESSION_DAYS * 86400) });
    }
    if (p === "/api/logout" && req.method === "POST") {
      const u = sessionUser(req); if (u) { delete state.sessions[u._token]; save(); }
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie("", 0) });
    }

    /* --- everything below needs a signed-in user --- */
    const u = sessionUser(req);
    if (!u) return err(res, 401, "unauthenticated", "Please sign in.");

    if (p === "/api/me/password" && req.method === "POST") {
      const b = await readBody(req);
      const pk = "pw|" + u.id;
      if (throttled(pk)) return err(res, 429, "resource_exhausted", "Too many attempts. Try again in 10 minutes.");
      if (!checkPassword(u, b.current || "")) { failed(pk); return err(res, 400, "invalid_argument", "Your current password is wrong."); }
      if (!validPassword(b.password)) return err(res, 400, "invalid_argument", "Passwords need at least 8 characters.");
      Object.assign(u, hashPassword(b.password));
      for (const [t, s] of Object.entries(state.sessions)) if (s.userId === u.id && t !== u._token) delete state.sessions[t];
      save(); return send(res, 200, { ok: true });
    }

    if (p === "/api/events" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
      res.write("retry: 3000\n\n");
      const c = { res, userId: u.id }; clients.add(c);
      req.on("close", () => clients.delete(c));
      return;
    }

    /* --- ping status (everyone signed in) and "check now" --- */
    if (p === "/api/ping" && req.method === "GET") return send(res, 200, pingPayload());
    if (p === "/api/ping/run" && req.method === "POST") {
      if (!pingSettings().enabled) return err(res, 400, "invalid_argument", "Ping checks are turned off in Settings.");
      if (Date.now() - ping.manualAt < 10000 || ping.running) return send(res, 200, { ok: true, queued: false });
      ping.manualAt = Date.now(); schedulePings(0);
      return send(res, 200, { ok: true, queued: true });
    }

    /* --- users (admins) --- */
    if (p === "/api/users" || p.startsWith("/api/users/")) {
      if (userRole(u) !== "admin") return err(res, 403, "forbidden", "Only admins can manage accounts.");
      const id = p.split("/")[3];
      if (!id && req.method === "GET") return send(res, 200, Object.values(state.users).map(publicUser));
      if (!id && req.method === "POST") {
        const b = await readBody(req);
        const username = String(b.username || "").trim();
        if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) return err(res, 400, "invalid_argument", "Usernames use letters, numbers and . _ @ - (2–64 characters).");
        if (findUser(username)) return err(res, 409, "conflict", `The username ${username} is taken.`);
        if (!validPassword(b.password)) return err(res, 400, "invalid_argument", "Passwords need at least 8 characters.");
        const nid = "u_" + crypto.randomBytes(8).toString("hex");
        state.users[nid] = { id: nid, username, name: String(b.name || "").trim(), email: String(b.email || "").trim(), role: ROLES.includes(b.role) ? b.role : "technician", created: new Date().toISOString(), ...hashPassword(b.password) };
        save(); return send(res, 200, publicUser(state.users[nid]));
      }
      const t = own(state.users, id) ? state.users[id] : null;
      if (!t) return err(res, 404, "not_found", "No such account.");
      if (req.method === "PATCH") {
        const b = await readBody(req);
        if (t.owner && (("role" in b && b.role !== "admin") || b.disabled)) return err(res, 400, "invalid_argument", "The owner account is always an active Admin.");
        if (t.owner && t.id !== u.id && ("password" in b || "name" in b || "email" in b)) return err(res, 403, "forbidden", "Only the owner can change the owner account.");
        if (t.id === u.id && b.disabled) return err(res, 400, "invalid_argument", "You can't disable your own account.");
        if ("role" in b) { if (!ROLES.includes(b.role)) return err(res, 400, "invalid_argument", "Unknown role."); t.role = b.role; }
        if ("name" in b) t.name = String(b.name || "").trim();
        if ("email" in b) t.email = String(b.email || "").trim();
        if ("disabled" in b) t.disabled = !!b.disabled;
        if ("password" in b) { if (!validPassword(b.password)) return err(res, 400, "invalid_argument", "Passwords need at least 8 characters."); Object.assign(t, hashPassword(b.password)); }
        if (t.disabled || "password" in b) for (const [k, s] of Object.entries(state.sessions)) if (s.userId === t.id && k !== u._token) delete state.sessions[k];
        save(); kickUser(t.id); broadcast({ type: "users" });
        return send(res, 200, publicUser(t));
      }
      if (req.method === "DELETE") {
        if (t.owner) return err(res, 400, "invalid_argument", "The owner account can't be deleted.");
        if (t.id === u.id) return err(res, 400, "invalid_argument", "You can't delete your own account.");
        delete state.users[id];
        for (const [k, s] of Object.entries(state.sessions)) if (s.userId === id) delete state.sessions[k];
        save(); kickUser(id); broadcast({ type: "users" });
        return send(res, 200, { ok: true });
      }
    }

    /* --- backup (admins) --- */
    if (p === "/api/backup" && req.method === "GET") {
      if (userRole(u) !== "admin") return err(res, 403, "forbidden", "Only admins can download backups.");
      const stamp = new Date().toISOString().slice(0, 10);
      res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="traffic-ip-backup-${stamp}.json"`, "Cache-Control": "no-store" });
      return res.end(JSON.stringify({ app: "Traffic-IP", version: VERSION, exported: new Date().toISOString(), collections: state.collections }, null, 1));
    }

    /* --- restore (admins): replace all app data in one step; accounts are left alone --- */
    if (p === "/api/restore" && req.method === "POST") {
      if (userRole(u) !== "admin") return err(res, 403, "forbidden", "Only admins can restore a backup.");
      const b = await readBody(req, 100 * 1024 * 1024);
      const c = b && b.collections;
      if (!c || typeof c !== "object" || typeof c.devices !== "object" || typeof c.intersections !== "object") return err(res, 400, "invalid_argument", "That file isn't a Traffic-IP backup.");
      const next = {};
      for (const [name, docs] of Object.entries(c)) {
        if (RESERVED.has(name)) continue;
        if (!SEG.test(name) || name.startsWith("_") || !docs || typeof docs !== "object" || Array.isArray(docs)) continue;
        next[name] = {};
        for (const [id, d] of Object.entries(docs)) if (SEG.test(id) && d && typeof d === "object" && !Array.isArray(d)) next[name][id] = d;
      }
      // keep a copy of what's being replaced, next to the automatic backups
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      fs.writeFileSync(path.join(BACKUP_DIR, `before-restore-${stamp}.json`), JSON.stringify({ app: "Traffic-IP", version: VERSION, exported: new Date().toISOString(), collections: state.collections }));
      state.collections = next;
      flushSync();
      console.log(`Backup restored by ${u.username}: ${Object.keys(next.devices || {}).length} devices, ${Object.keys(next.intersections || {}).length} intersections.`);
      setTimeout(() => broadcast({ type: "reload" }), 300);   // every open page reloads with the restored data
      schedulePings(1000);
      return send(res, 200, { ok: true });
    }

    /* --- locks (cooperative leases for IP assignment) --- */
    const lockM = p.match(/^\/api\/lock\/([^/]+)\/([^/]+)$/);
    if (lockM && req.method === "POST") {
      const [, c, id] = lockM;
      if (!SEG.test(c) || !SEG.test(id)) return err(res, 400, "invalid_argument", "Bad path.");
      if (!writeAllowed(u, "locks", id, "update")) return err(res, 403, "forbidden", "Not allowed.");
      const b = await readBody(req);
      const key = c + "/" + id, now = Date.now();
      const ttl = Math.min(600000, Math.max(1000, +b.ttlMs || 30000));
      const cur = leases.get(key);
      if (cur && cur.expires > now && cur.holder !== b.holder) return send(res, 200, { acquired: false, expiresAt: new Date(cur.expires).toISOString() });
      leases.set(key, { holder: String(b.holder || ""), expires: now + ttl });
      return send(res, 200, { acquired: true, holder: b.holder, expiresAt: new Date(now + ttl).toISOString() });
    }

    /* --- documents --- */
    const m = p.match(/^\/api\/data\/([^/]+)(?:\/([^/]+))?$/);
    if (m) {
      const [, c, id] = m;
      if (!SEG.test(c) || (id && !SEG.test(id)) || c.startsWith("_")) return err(res, 400, "invalid_argument", "Bad path.");
      if (req.method === "GET") {
        if (!id) return send(res, 200, Object.entries(peek(c)).map(([k, v]) => ({ id: k, data: v })));
        const d = own(peek(c), id) ? peek(c)[id] : undefined;
        return send(res, 200, d ? { id, exists: true, data: d } : { id, exists: false });
      }
      if (!id) return err(res, 400, "invalid_argument", "Missing id.");
      if (req.method === "PUT") {
        const exists = own(peek(c), id);
        if (!writeAllowed(u, c, id, exists ? "update" : "create")) return err(res, 403, "forbidden", "Your role doesn't allow that change.");
        const data = await readBody(req);
        const v = validate(c, id, data);
        if (v) return v.conflict ? err(res, 409, "conflict", v.conflict) : err(res, 400, "invalid_argument", v);
        coll(c)[id] = data; save();
        broadcast({ type: "change", coll: c, id, data });
        if (c === "admin" && id === "settings") schedulePings(0);
        return send(res, 200, { ok: true });
      }
      if (req.method === "DELETE") {
        if (!writeAllowed(u, c, id, "delete")) return err(res, 403, "forbidden", "Your role doesn't allow that change.");
        delete coll(c)[id]; save();
        broadcast({ type: "change", coll: c, id, data: null });
        return send(res, 200, { ok: true });
      }
    }
    return err(res, 404, "not_found", "Not found.");
  } catch (e) {
    console.error(e);
    if (!res.headersSent) err(res, e.message === "too large" ? 413 : 400, "invalid_argument", e.message === "too large" ? "Request too large." : "Bad request.");
  }
});

schedulePings(3000);
server.listen(PORT, () => {
  console.log(`Traffic-IP v${VERSION} running on port ${PORT} (data in ${DATA_DIR})`);
  if (!Object.keys(state.users).length) console.log("No accounts yet — open the app in a browser to create the owner account.");
});
