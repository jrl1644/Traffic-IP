// Standalone mode: replaces claude.ai's storage + sign-in with this server's API.
// Loaded before the app script; provides window.claude.use("db" | "user").
(function () {
  "use strict";
  window.__STANDALONE = true;

  /* ---------- API ---------- */
  async function api(method, url, body) {
    const r = await fetch(url, {
      method, credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "iid" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let j = null; try { j = await r.json(); } catch {}
    if (!r.ok) {
      if (r.status === 401 && !/\/api\/(login|setup|me\/password)/.test(url)) { location.reload(); }
      const e = j?.error || { code: "unavailable", message: "The server couldn't be reached." };
      throw { code: e.code, message: e.message, status: r.status };
    }
    return j;
  }
  window.__api = api;

  /* ---------- sign-in / first-run screen ---------- */
  let session = null;
  const ready = (async () => {
    let s;
    for (;;) {
      try { s = await api("GET", "/api/session"); break; }
      catch { await new Promise(r => setTimeout(r, 2000)); }
    }
    if (s.user) { session = s.user; return; }
    await new Promise(resolve => showAuth(s.needsSetup, resolve));
    session = (await api("GET", "/api/session")).user;
  })();

  function showAuth(setup, done) {
    const host = document.createElement("div");
    host.id = "authScreen";
    host.innerHTML = `
      <style>
        #authScreen{position:fixed;inset:0;z-index:50;background:var(--bg,#f4f5f2);display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--sans,system-ui)}
        #authScreen form{background:var(--panel,#fff);border:1px solid var(--line,#ddd);border-radius:12px;padding:26px;width:100%;max-width:380px;box-shadow:0 10px 30px rgba(0,0,0,.08)}
        #authScreen h1{margin:0 0 4px;font-size:20px;color:var(--ink,#111)} #authScreen p{margin:0 0 16px;color:var(--muted,#666);font-size:14px}
        #authScreen label{display:block;font-size:12px;font-weight:600;color:var(--muted,#666);text-transform:uppercase;letter-spacing:.4px;margin:10px 0 4px}
        #authScreen input{width:100%;box-sizing:border-box;font:inherit;font-size:15px;padding:9px 10px;border:1px solid var(--line,#ccc);border-radius:8px;background:var(--panel,#fff);color:var(--ink,#111)}
        #authScreen button{margin-top:16px;width:100%;font:inherit;font-weight:600;padding:10px;border-radius:8px;border:none;background:var(--accent,#e0a100);color:#1c2321;cursor:pointer}
        #authScreen .err{color:var(--danger,#b3261e);font-size:13px;min-height:18px;margin-top:10px}
        #authScreen .bar{height:6px;background:var(--sign,#1f6f4a);border-radius:12px 12px 0 0;margin:-26px -26px 20px}
      </style>
      <form novalidate>
        <div class="bar"></div>
        <h1>Traffic IP</h1>
        <p>${setup ? "Welcome! Create the owner account. The owner is always an Admin." : "Sign in to continue."}</p>
        ${setup ? `<label>Your name</label><input name="name" autocomplete="name">` : ""}
        <label>Username</label><input name="username" autocomplete="username" required>
        <label>Password</label><input name="password" type="password" autocomplete="${setup ? "new-password" : "current-password"}" required>
        ${setup ? `<label>Confirm password</label><input name="confirm" type="password" autocomplete="new-password">` : ""}
        <button type="submit">${setup ? "Create owner account" : "Sign in"}</button>
        <div class="err" role="alert"></div>
      </form>`;
    const mount = () => { document.body.appendChild(host); host.querySelector("input").focus(); };
    document.body ? mount() : document.addEventListener("DOMContentLoaded", mount);
    const f = host.querySelector("form"), errEl = host.querySelector(".err");
    f.addEventListener("submit", async e => {
      e.preventDefault();
      const v = Object.fromEntries(new FormData(f));
      if (setup && v.password !== v.confirm) { errEl.textContent = "The passwords don't match."; return; }
      f.querySelector("button").disabled = true; errEl.textContent = "";
      try { await api("POST", setup ? "/api/setup" : "/api/login", v); host.remove(); done(); }
      catch (ex) { errEl.textContent = ex.message || "Couldn't sign in."; }
      finally { f.querySelector("button").disabled = false; }
    });
  }

  /* ---------- live data cache ---------- */
  const cache = {};            // coll -> Map(id -> data)
  const loaded = {};           // coll -> Promise
  const colSubs = {};          // coll -> Set(fn)
  const docSubs = {};          // "coll/id" -> Set(fn)
  const freeze = o => o;       // keep plain objects
  const mkDoc = (id, data) => ({ id, exists: data !== undefined && data !== null, data: () => (data == null ? undefined : data), metadata: { fromCache: false, hasPendingWrites: false } });
  const mkSnap = c => {
    const docs = [...(cache[c] || new Map()).entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([id, d]) => mkDoc(id, d));
    return { docs, size: docs.length, empty: !docs.length, docChanges: () => docs.map((doc, i) => ({ type: "added", doc, oldIndex: -1, newIndex: i })), metadata: { fromCache: false, hasPendingWrites: false } };
  };
  function load(c) {
    return (loaded[c] ||= api("GET", `/api/data/${encodeURIComponent(c)}`).then(rows => { cache[c] = new Map(rows.map(r => [r.id, freeze(r.data)])); }));
  }
  function apply(c, id, data) {
    if (!cache[c]) return;
    if (data === null) cache[c].delete(id); else cache[c].set(id, data);
    (colSubs[c] || []).forEach(fn => fn(mkSnap(c)));
    (docSubs[c + "/" + id] || []).forEach(fn => fn(mkDoc(id, data)));
  }
  // one live stream for everything
  let es = null;
  function connect() {
    es = new EventSource("/api/events");
    es.onmessage = ev => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === "change") apply(m.coll, m.id, m.data);
      if (m.type === "reload") location.reload();
      if (m.type === "users") window.dispatchEvent(new Event("iid-users-changed"));
    };
    es.onerror = () => {
      // after a reconnect, refresh everything we've loaded in case we missed changes
      es.addEventListener("open", () => Object.keys(cache).forEach(c => { delete loaded[c]; load(c).then(() => { (colSubs[c] || []).forEach(fn => fn(mkSnap(c))); Object.keys(docSubs).filter(k => k.startsWith(c + "/")).forEach(k => { const id = k.slice(c.length + 1); docSubs[k].forEach(fn => fn(mkDoc(id, cache[c].get(id)))); }); }); }), { once: true });
    };
  }

  const randId = () => Array.from(crypto.getRandomValues(new Uint8Array(10)), b => b.toString(36).padStart(2, "0")).join("").slice(0, 20);
  function docRef(c, id) {
    return {
      id, path: `${c}/${id}`,
      async get() { await load(c); return mkDoc(id, cache[c].get(id)); },
      async set(data) { await api("PUT", `/api/data/${encodeURIComponent(c)}/${encodeURIComponent(id)}`, data); await load(c); apply(c, id, data); },
      async update(data) { await load(c); const cur = cache[c].get(id); if (!cur) throw { code: "invalid_argument", message: "Document doesn't exist." }; return this.set({ ...cur, ...data }); },
      async delete() { await api("DELETE", `/api/data/${encodeURIComponent(c)}/${encodeURIComponent(id)}`); await load(c); apply(c, id, null); },
      async acquire(o) { return api("POST", `/api/lock/${encodeURIComponent(c)}/${encodeURIComponent(id)}`, o || {}); },
      onSnapshot(next, error) {
        const k = c + "/" + id; (docSubs[k] ||= new Set()).add(next);
        load(c).then(() => next(mkDoc(id, cache[c].get(id)))).catch(e => error && error({ code: "unavailable", message: e.message }));
        return () => docSubs[k].delete(next);
      },
      collection(sub) { throw new TypeError("Sub-collections aren't used in standalone mode."); },
    };
  }
  function collRef(c) {
    const q = {
      path: c,
      doc: id => docRef(c, id || randId()),
      async add(data) { const r = docRef(c, randId()); await r.set(data); return r; },
      where() { return q; }, orderBy() { return q; }, limit() { return q; },
      async get() { await load(c); return mkSnap(c); },
      onSnapshot(next, error) {
        (colSubs[c] ||= new Set()).add(next);
        load(c).then(() => next(mkSnap(c))).catch(e => error && error({ code: "unavailable", message: e.message }));
        return () => colSubs[c].delete(next);
      },
    };
    return q;
  }
  const db = {
    collection: c => collRef(c),
    doc: p => { const [c, id] = String(p).split("/"); return docRef(c, id); },
  };

  /* ---------- user ---------- */
  const user = {
    isOwner: async () => !!session?.owner,
    canEdit: async () => session?.role === "admin",
    can: async name => name === "data.write" ? !!session?.canWrite : null,
    me: async () => ({ id: session?.id || null, name: session?.name || session?.username || "", email: session?.email || null, avatarUrl: "", color: "#1f6f4a", isOwner: !!session?.owner, canEdit: session?.role === "admin", role: session?.role, username: session?.username }),
    id: async () => session?.id || null,
    profiles: async ids => Object.fromEntries([].concat(ids).map(id => [id, { id, name: "", avatarUrl: "", color: "#888", email: null, isMe: id === session?.id, guest: false }])),
    search: async () => [],
  };

  window.claude = {
    use: async name => {
      await ready;
      if (!es) connect();
      return name === "db" ? db : name === "user" ? user : null;
    },
  };
  window.__session = () => session;
})();
