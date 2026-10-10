import "./style.css";
import {
  claimName, createIdentity, exportSecret, loadPetnames, loadRegistry, loadZone, peekIdentity, pinNames, REGISTRY_ADMIN,
  replaceIdentity, resolve, savePetnames, setRecord, webUrl,
} from "./lib";
import { contractId, isKey, resolveOwner, ROOT, validName } from "./names";

const app = document.getElementById("app")!;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const $ = <T extends HTMLElement>(sel: string) => app.querySelector(sel) as T;
const val = (sel: string) => $<HTMLInputElement>(sel).value.trim();
const short = (k: string) => `${k.slice(0, 8)}…${k.slice(-6)}`;

/** Run `f` from a button: disable it, show progress and errors in `out`. */
const act = (btn: string, out: string, f: () => Promise<string | void>) => {
  $<HTMLButtonElement>(btn).onclick = async () => {
    const b = $<HTMLButtonElement>(btn), o = $(out);
    b.disabled = true; o.className = "muted"; o.textContent = "Working…";
    try { o.textContent = (await f()) ?? "Done."; }
    catch (e) { o.className = "err"; o.textContent = String((e as Error).message ?? e); }
    b.disabled = false;
  };
};

// route: #/ resolve | #/go/<name> | #/mine | #/admin (not linked anywhere)
function route() {
  if (window.parent !== window) parent.postMessage({ __freenet_shell__: true, type: "hash", hash: location.hash || "#/" }, "*");
  const h = location.hash;
  document.querySelectorAll<HTMLElement>("[data-nav]").forEach((a) => a.toggleAttribute("aria-current", a.getAttribute("href") === (h || "#/")));
  if (h === "#/mine") return minePage();
  if (h === "#/admin") return adminPage();
  const go = h.match(/^#\/go\/(.+)$/);
  return resolvePage(go ? decodeURIComponent(go[1]) : "");
}

// ---------------- resolve ----------------
function resolvePage(initial: string) {
  app.innerHTML = `
    <h1>Find a site by name</h1>
    <p class="muted"><code>name</code> opens the site a name points to, <code>name/sub</code> one of its sub-names. Your petnames come first, then the public registry.</p>
    <form id="f" class="row"><input id="q" placeholder="scobru/freetunes" autocomplete="off" spellcheck="false" value="${esc(initial)}" /><button class="primary">Resolve</button></form>
    <div id="out"></div>`;
  const run = async (q: string) => {
    const out = $("#out");
    out.innerHTML = `<p class="muted">Looking up…</p>`;
    try {
      const r = await resolve(q);
      if (!r.owner) { out.innerHTML = `<p class="err">Nobody holds this name.</p>`; return; }
      const who = `owner <code title="${r.owner}">${short(r.owner)}</code> (via ${r.via})`;
      out.innerHTML = r.target
        ? `<div class="card"><p><a class="btn primary" href="${webUrl(r.target)}" target="_blank" rel="noopener">Open ${esc(q)}</a></p>
           <p class="muted"><small>${who} · contract <code>${esc(r.target)}</code></small></p></div>`
        : `<p class="err">The owner has not set <code>${esc(r.sub)}</code>.</p><p class="muted"><small>${who}</small></p>`;
    } catch (e) { out.innerHTML = `<p class="err">${esc(String((e as Error).message ?? e))}</p>`; }
  };
  $("#f").onsubmit = (e) => {
    e.preventDefault();
    history.replaceState(null, "", `#/go/${encodeURIComponent(val("#q"))}`);
    run(val("#q"));
  };
  if (initial) run(initial);
}

// ---------------- my names ----------------
async function minePage() {
  app.innerHTML = `<h1>My names</h1><div id="box"><p class="muted">Loading…</p></div>`;
  const me = await peekIdentity().catch(() => null);
  if (!me) {
    $("#box").innerHTML = `
      <p class="muted">Your names belong to a key kept by your node. Create one, or import a secret key you exported before.</p>
      <p><button id="new" class="primary">Create a key</button></p>
      <div class="card"><h2>Import</h2><div class="row"><input id="isk" type="password" placeholder="secret key (64 hex)" autocomplete="off" /><button id="imp">Import</button></div><p id="io"></p></div>`;
    act("#new", "#io", async () => { await createIdentity(); minePage(); });
    act("#imp", "#io", async () => { await replaceIdentity(val("#isk")); minePage(); });
    return;
  }
  const [zone, reg, pets] = await Promise.all([loadZone(me.pk), loadRegistry().catch(() => null), loadPetnames()]);
  const records = Object.entries(zone?.records ?? {}).filter(([, r]) => r.target);
  const held = reg ? Object.keys(reg.claims).filter((n) => resolveOwner(REGISTRY_ADMIN, reg, n) === me.pk) : [];
  $("#box").innerHTML = `
    <div class="card">
      <h2>Key</h2>
      <p><code class="wrap">${me.pk}</code></p>
      <p class="muted"><small>Others can always reach your names as <code>${short(me.pk)}/name</code>, even without the registry.${me.persisted ? "" : " <b>This browser cannot keep the key: export it.</b>"}</small></p>
      <p><button id="exp">Show secret key</button> <span id="eo"></span></p>
    </div>
    <div class="card">
      <h2>Your zone</h2>
      <p class="muted"><code>@</code> is what your bare name opens; any other name is a sub-name (<code>you/music</code>).</p>
      <table>${records.map(([n, r]) => `<tr><td><code>${esc(n)}</code></td><td><code>${esc(r.target)}</code></td><td><button class="small danger" data-del="${esc(n)}">Remove</button></td></tr>`).join("") || `<tr><td class="muted">No records yet.</td></tr>`}</table>
      <div class="row"><input id="rn" placeholder="@ or sub-name" value="${ROOT}" autocomplete="off" /><input id="rt" placeholder="contract id or node URL" autocomplete="off" /><button id="rs" class="primary">Save</button></div>
      <p id="ro"></p>
    </div>
    <div class="card">
      <h2>Registry name</h2>
      <p class="muted">A short global name for your key. Claiming costs a few seconds of work. If others claim the same name, the strongest proof wins unless the registry admin pins it.</p>
      <p>${held.length ? `You hold: ${held.map((n) => `<code>${esc(n)}</code>`).join(", ")}` : `<span class="muted">You hold no registry name.</span>`}</p>
      <div class="row"><input id="cn" placeholder="name" autocomplete="off" /><button id="cl" class="primary">Claim</button></div>
      <p id="co"></p>
    </div>
    <div class="card">
      <h2>Petnames</h2>
      <p class="muted">Your own names for other people's keys. They override the registry, on this node only.</p>
      <table>${Object.entries(pets).map(([n, k]) => `<tr><td><code>${esc(n)}</code></td><td><code title="${esc(k)}">${short(k)}</code></td><td><button class="small danger" data-pet="${esc(n)}">Remove</button></td></tr>`).join("") || `<tr><td class="muted">None.</td></tr>`}</table>
      <div class="row"><input id="pn" placeholder="name" autocomplete="off" /><input id="pk" placeholder="their key (64 hex)" autocomplete="off" /><button id="ps">Add</button></div>
      <p id="po"></p>
    </div>`;

  $("#exp").onclick = async () => {
    if (!confirm("Anyone who sees this key controls your names. Show it?")) return;
    $("#eo").innerHTML = `<code class="wrap">${await exportSecret().catch((e) => esc(String(e)))}</code>`;
  };
  act("#rs", "#ro", async () => {
    const n = val("#rn"), t = contractId(val("#rt"));
    if (n !== ROOT && !validName(n)) throw new Error("Name: lowercase letters, digits and inner hyphens.");
    if (!t) throw new Error("Paste a contract id or a node URL.");
    await setRecord(n, t);
    minePage();
  });
  app.querySelectorAll<HTMLButtonElement>("[data-del]").forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    await setRecord(b.dataset.del!, "").catch((e) => alert(e));
    minePage();
  }));
  act("#cl", "#co", async () => {
    const n = val("#cn");
    if (!validName(n)) throw new Error("Name: lowercase letters, digits and inner hyphens.");
    $("#co").textContent = "Mining the proof of work…";
    await claimName(n);
    return `Claimed. It resolves to you unless a stronger claim or a pin says otherwise.`;
  });
  act("#ps", "#po", async () => {
    const n = val("#pn"), k = val("#pk").toLowerCase();
    if (!validName(n) || !isKey(k)) throw new Error("A valid name and a 64-hex key, please.");
    await savePetnames({ ...pets, [n]: k });
    minePage();
  });
  app.querySelectorAll<HTMLButtonElement>("[data-pet]").forEach((b) => (b.onclick = async () => {
    const { [b.dataset.pet!]: _, ...rest } = pets;
    await savePetnames(rest);
    minePage();
  }));
}

// ---------------- admin ----------------
async function adminPage() {
  const reg = await loadRegistry().catch(() => null);
  const lines = Object.entries(reg?.pins.map ?? {}).map(([n, o]) => `${n}=${o}`).join("\n");
  app.innerHTML = `
    <h1>Registry admin</h1>
    <p class="muted">One pin per line: <code>name=owner key</code>, or <code>name=</code> to reserve a name. This replaces all pins.</p>
    <textarea id="pins" rows="8" spellcheck="false">${esc(lines)}</textarea>
    <div class="row"><input id="ask" type="password" placeholder="admin secret key (64 hex)" autocomplete="off" /><button id="go" class="primary">Publish pins</button></div>
    <p id="o"></p>`;
  act("#go", "#o", async () => {
    const map: Record<string, string> = {};
    for (const l of val("#pins").split("\n").map((s) => s.trim()).filter(Boolean)) {
      const [n, o = ""] = l.split("=");
      if (!validName(n) || (o && !isKey(o))) throw new Error(`Bad line: ${l}`);
      map[n] = o;
    }
    await pinNames(val("#ask"), map);
  });
}

addEventListener("hashchange", route);
route();
