// Traffic-IP — standalone server
const VERSION = "11.11.26-3";   // MM.DD.YY-revision — keep in step with APP_VERSION in app-source.html
// No external dependencies: Node.js 20+ built-ins only.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "8187", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE || "");
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

const coll = name => (state.collections[name] ||= {});

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
  const cfg = coll("admin").config || {};
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
function newSession(u) {
  const token = crypto.randomBytes(32).toString("hex");
  state.sessions[token] = { userId: u.id, expires: Date.now() + SESSION_DAYS * 864e5 };
  u.lastLogin = new Date().toISOString(); save();
  return token;
}
function sessionUser(req) {
  const m = /(?:^|;\s*)iid_session=([a-f0-9]{64})/.exec(req.headers.cookie || "");
  if (!m) return null;
  const s = state.sessions[m[1]];
  if (!s || s.expires < Date.now()) { if (s) { delete state.sessions[m[1]]; save(); } return null; }
  const u = state.users[s.userId];
  if (!u || u.disabled) return null;
  return Object.assign(u, { _token: m[1] });
}
function cookie(token, maxAge) {
  return `iid_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${COOKIE_SECURE ? "; Secure" : ""}`;
}
// simple login throttle: 10 failures per 10 minutes per IP+username
const fails = new Map();
function throttled(key) { const f = fails.get(key); return f && f.n >= 10 && Date.now() - f.t < 600e3; }
function failed(key) { const f = fails.get(key) || { n: 0, t: Date.now() }; if (Date.now() - f.t > 600e3) { f.n = 0; f.t = Date.now(); } f.n++; fails.set(key, f); }

// first admin from environment, if provided and no users exist
if (!Object.keys(state.users).length && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  const id = "u_" + crypto.randomBytes(8).toString("hex");
  state.users[id] = { id, username: process.env.ADMIN_USERNAME.trim(), name: process.env.ADMIN_NAME || "Administrator", owner: true, role: "admin", created: new Date().toISOString(), ...hashPassword(process.env.ADMIN_PASSWORD) };
  flushSync();
  console.log(`Created owner account "${process.env.ADMIN_USERNAME}" from environment.`);
}

const leases = new Map();   // in memory only

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
    const doc = coll("intersections")[id]; if (!doc) return true;
    const a = normStreet(doc.street1), b = normStreet(doc.street2);
    return !Object.values(coll("devices")).some(d => { const x = normStreet(d.street1), y = normStreet(d.street2); return (x === a && y === b) || (x === b && y === a); });
  }
  return false;
}
function validate(c, id, data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return "Body must be an object.";
  if (c === "devices") {
    const ip = String(data.ip || "").trim();
    if (!ip) return "A device needs an IP address.";
    const taken = Object.entries(coll("devices")).find(([k, d]) => k !== id && String(d.ip).trim() === ip);
    if (taken) return { conflict: `IP ${ip} is already used by “${taken[1].name}”. Duplicate IPs aren't allowed.` };
  }
  return null;
}
const SEG = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;

/* ------------------------------------------------------------------ http helpers */
function send(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}
const err = (res, code, errCode, message) => send(res, code, { error: { code: errCode, message } });
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", ch => { size += ch.length; if (size > MAX_BODY) { reject(new Error("too large")); req.destroy(); } else chunks.push(ch); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json" };
function serveStatic(req, res, urlPath) {
  let p = urlPath === "/" ? "/index.html" : urlPath;
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end("Not found"); }
  res.writeHead(200, {
    "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
    "Cache-Control": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "SAMEORIGIN",
  });
  fs.createReadStream(file).pipe(res);
}

/* ------------------------------------------------------------------ routes */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  try {
    if (!p.startsWith("/api/")) return serveStatic(req, res, p);
    if (p === "/api/health") return send(res, 200, { ok: true, version: VERSION });

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
      const key = (req.socket.remoteAddress || "") + "|" + String(b.username || "").toLowerCase();
      if (throttled(key)) return err(res, 429, "resource_exhausted", "Too many attempts. Try again in 10 minutes.");
      const u = findUser(b.username);
      if (!u || !checkPassword(u, b.password || "")) { failed(key); return err(res, 401, "unauthenticated", "Wrong username or password."); }
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
      if (!checkPassword(u, b.current || "")) return err(res, 400, "invalid_argument", "Your current password is wrong.");
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
      const t = state.users[id];
      if (!t) return err(res, 404, "not_found", "No such account.");
      if (req.method === "PATCH") {
        const b = await readBody(req);
        if (t.owner && (("role" in b && b.role !== "admin") || b.disabled)) return err(res, 400, "invalid_argument", "The owner account is always an active Admin.");
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
      res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="traffic-ip-backup-${stamp}.json"` });
      return res.end(JSON.stringify({ exported: new Date().toISOString(), collections: state.collections }, null, 1));
    }

    /* --- locks (cooperative leases for IP assignment) --- */
    const lockM = p.match(/^\/api\/lock\/([^/]+)\/([^/]+)$/);
    if (lockM && req.method === "POST") {
      const [, c, id] = lockM;
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
        if (!id) return send(res, 200, Object.entries(coll(c)).map(([k, v]) => ({ id: k, data: v })));
        const d = coll(c)[id];
        return send(res, 200, d ? { id, exists: true, data: d } : { id, exists: false });
      }
      if (!id) return err(res, 400, "invalid_argument", "Missing id.");
      if (req.method === "PUT") {
        const exists = !!coll(c)[id];
        if (!writeAllowed(u, c, id, exists ? "update" : "create")) return err(res, 403, "forbidden", "Your role doesn't allow that change.");
        const data = await readBody(req);
        const v = validate(c, id, data);
        if (v) return v.conflict ? err(res, 409, "conflict", v.conflict) : err(res, 400, "invalid_argument", v);
        coll(c)[id] = data; save();
        broadcast({ type: "change", coll: c, id, data });
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

server.listen(PORT, () => {
  console.log(`Traffic-IP v${VERSION} running on port ${PORT} (data in ${DATA_DIR})`);
  if (!Object.keys(state.users).length) console.log("No accounts yet — open the app in a browser to create the owner account.");
});
