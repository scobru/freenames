import "./style.css";
import {
  claimName, finishSignIn, loadPetnames, loadRegistry, loadZone, officialWhoiam, personaName, pinNames, REGISTRY_ADMIN,
  resolve, savePetnames, search, session, setRecord, signOut, startSignIn, webUrl, type Session,
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

// route: #/ resolve | #/go/<name> | #/mine | #/how | #/admin (not linked anywhere); ?viso=... or ?whoiam=... is callback
function route() {
  if (window.parent !== window) parent.postMessage({ __freenet_shell__: true, type: "hash", hash: location.hash || "#/" }, "*");
  const h = location.hash;
  document.querySelectorAll<HTMLElement>("[data-nav]").forEach((a) => a.toggleAttribute("aria-current", a.getAttribute("href") === (h || "#/")));
  const q = new URLSearchParams(location.search);
  if (q.has("viso") || q.has("whoiam")) return signInCallback(q);
  if (h === "#/mine") return minePage();
  if (h === "#/how") return howPage();
  if (h === "#/admin") return adminPage();
  const go = h.match(/^#\/go\/(.+)$/);
  return resolvePage(go ? decodeURIComponent(go[1]) : "");
}

// ---------------- resolve ----------------
function resolvePage(initial: string) {
  app.innerHTML = `
    <h1>Find a site by name</h1>
    <p class="muted"><code>name</code> opens the site a name points to, <code>name/sub</code> one of its sub-names, and any part of a name finds every name that contains it. Your petnames come first, then the public registry.</p>
    <form id="f" class="row"><input id="q" placeholder="scobru/freetunes" autocomplete="off" spellcheck="false" value="${esc(initial)}" /><button class="primary">Search</button></form>
    <div id="out"></div>`;
  const run = async (q: string) => {
    const out = $("#out");
    out.innerHTML = `<div id="exact"><p class="muted">Looking up…</p></div><div id="hits"></div>`;
    const exact = $("#exact");
    try {
      const r = await resolve(q);
      const who = r.owner ? `owner: Viso persona <code title="${r.owner}">${esc(personaName(r.owner))}</code> (via ${r.via})` : "";
      exact.innerHTML = !r.owner ? `<p class="muted">No exact match for <code>${esc(q)}</code>.</p>`
        : r.target
          ? `<div class="card"><p><a class="btn primary" href="${webUrl(r.target)}" target="_blank" rel="noopener">Open ${esc(q)}</a></p>
             <p class="muted"><small>${who} · contract <code>${esc(r.target)}</code></small></p></div>`
          : `<p class="err">The owner has not set <code>${esc(r.sub)}</code>.</p><p class="muted"><small>${who}</small></p>`;
    } catch { exact.innerHTML = ""; } // not a name (e.g. a partial word): the search below still runs
    // partial matches: every known name containing the query
    const hits = $("#hits"), needle = q.trim().toLowerCase().replace(/^fn:/, "");
    const seen = new Set([needle]);
    hits.innerHTML = `<h2>Names containing “${esc(needle)}”</h2><ul id="hl"></ul><p class="muted" id="hs">Searching…</p>`;
    try {
      await search(needle, (h) => {
        if (seen.has(h.name)) return;
        seen.add(h.name);
        $("#hl").insertAdjacentHTML("beforeend", `<li><a href="${webUrl(h.target)}" target="_blank" rel="noopener"><code>${esc(h.name)}</code></a> <small class="muted">by ${esc(personaName(h.owner).slice(0, 10))}…</small></li>`);
      });
      $("#hs").textContent = seen.size > 1 ? "" : "None found.";
    } catch (e) { $("#hs").textContent = String((e as Error).message ?? e); }
  };
  $("#f").onsubmit = (e) => {
    e.preventDefault();
    history.replaceState(null, "", `#/go/${encodeURIComponent(val("#q"))}`);
    run(val("#q"));
  };
  if (initial) return void run(initial);
  // no query: list the first registered sites (registry order), so there is something to browse
  $("#out").innerHTML = `<h2>Registered sites</h2><ul id="rl"></ul><p class="muted" id="rs">Loading…</p>`;
  let count = 0;
  search("", (h) => {
    count++;
    app.querySelector("#rl")?.insertAdjacentHTML("beforeend", `<li><a href="${webUrl(h.target)}" target="_blank" rel="noopener"><code>${esc(h.name)}</code></a> <small class="muted">by ${esc(personaName(h.owner).slice(0, 10))}…</small></li>`);
  }, 50).then(() => { const s = app.querySelector("#rs"); if (s) s.textContent = count ? "" : "No sites registered yet."; },
    (e) => { const s = app.querySelector("#rs"); if (s) s.textContent = String((e as Error).message ?? e); });
}

// ---------------- my names ----------------
async function minePage() {
  app.innerHTML = `<h1>My names</h1><div id="box"><p class="muted">Connecting to the node (up to about 10 s the first time)…</p></div>`;
  let me: Session | null;
  try { me = await session(); }
  catch (e) { $("#box").innerHTML = `<p class="err">Could not reach the node: ${esc(String((e as Error).message ?? e))}</p>`; return; }
  if (!me) {
    $("#box").innerHTML = `
      <p class="muted">Your names belong to your <b>Viso</b> persona. Sign in once on this node: Viso opens, you pick a persona, and it lets this app write on its behalf. No key or seed is shared, and there is nothing to back up here.</p>
      <div class="row"><input id="wurl" value="${esc(officialWhoiam())}" spellcheck="false" autocomplete="off" /><button id="wgo" class="primary">Sign in with Viso</button></div>
      <p id="wo"></p>`;
    act("#wgo", "#wo", async () => { goTo(await startSignIn(val("#wurl"))); return "Opening Viso…"; });
    return;
  }
  const pk = me.persona;
  const loading = `<tr><td class="muted">Loading from the node (can take up to 30 s)…</td></tr>`;
  $("#box").innerHTML = `
    <div class="card">
      <h2>Signed in</h2>
      <p>Viso persona <code>${esc(personaName(pk))}</code></p>
      <p class="muted"><small>Your persona key: <code class="wrap">${pk}</code>. Others can always reach your names as <code>&lt;this key&gt;/name</code>, even without the registry.</small></p>
      <p><button id="so">Sign out</button></p>
    </div>
    <div class="card">
      <h2>Your zone</h2>
      <p class="muted"><code>@</code> is what your bare name opens; any other name is a sub-name (<code>you/music</code>).</p>
      <table id="zt">${loading}</table>
      <div class="row"><input id="rn" placeholder="@ or sub-name" value="${ROOT}" autocomplete="off" /><input id="rt" placeholder="contract id or node URL" autocomplete="off" /><button id="rs" class="primary">Save</button></div>
      <p id="ro"></p>
    </div>
    <div class="card">
      <h2>Registry name</h2>
      <p class="muted">A short global name for your key. Claiming costs a few seconds of work. If others claim the same name, the strongest proof wins unless the registry admin pins it.</p>
      <p id="held" class="muted">Loading the registry…</p>
      <div class="row"><input id="cn" placeholder="name" autocomplete="off" /><button id="cl" class="primary">Claim</button></div>
      <p id="co"></p>
    </div>
    <div class="card">
      <h2>Petnames</h2>
      <p class="muted">Your own names for other people's keys. They override the registry, on this node only.</p>
      <table id="pt">${loading}</table>
      <div class="row"><input id="pn" placeholder="name" autocomplete="off" /><input id="pk" placeholder="their persona key (64 hex)" autocomplete="off" /><button id="ps">Add</button></div>
      <p id="po"></p>
    </div>`;
  const fail = (e: unknown) => `<span class="err">${esc(String((e as Error).message ?? e))}</span>`;

  // each section loads on its own, so a slow contract does not hold up the rest
  loadZone(pk).then((zone) => {
    const records = Object.entries(zone?.records ?? {}).filter(([, r]) => r.target);
    $("#zt").innerHTML = records.map(([n, r]) => `<tr><td><code>${esc(n)}</code></td><td><code>${esc(r.target)}</code></td><td><button class="small danger" data-del="${esc(n)}">Remove</button></td></tr>`).join("")
      || `<tr><td class="muted">${zone ? "No records yet." : "No zone yet: saving a record creates it."}</td></tr>`;
    app.querySelectorAll<HTMLButtonElement>("[data-del]").forEach((b) => (b.onclick = async () => {
      b.disabled = true;
      await setRecord(b.dataset.del!, "").catch((e) => alert(e));
      minePage();
    }));
  }, (e) => ($("#zt").innerHTML = `<tr><td>${fail(e)}</td></tr>`));

  loadRegistry().then((reg) => {
    const held = Object.keys(reg.claims).filter((n) => resolveOwner(REGISTRY_ADMIN, reg, n) === pk);
    $("#held").innerHTML = held.length ? `You hold: ${held.map((n) => `<code>${esc(n)}</code>`).join(", ")}` : "You hold no registry name.";
  }, (e) => ($("#held").innerHTML = fail(e)));

  let pets: Record<string, string> = {};
  loadPetnames().then((p) => {
    pets = p;
    $("#pt").innerHTML = Object.entries(pets).map(([n, k]) => `<tr><td><code>${esc(n)}</code></td><td><code title="${esc(k)}">${short(k)}</code></td><td><button class="small danger" data-pet="${esc(n)}">Remove</button></td></tr>`).join("") || `<tr><td class="muted">None.</td></tr>`;
    app.querySelectorAll<HTMLButtonElement>("[data-pet]").forEach((b) => (b.onclick = async () => {
      const { [b.dataset.pet!]: _, ...rest } = pets;
      await savePetnames(rest);
      minePage();
    }));
  }, (e) => ($("#pt").innerHTML = `<tr><td>${fail(e)}</td></tr>`));

  $("#so").onclick = async () => { await signOut(); minePage(); };
  act("#rs", "#ro", async () => {
    const n = val("#rn"), t = contractId(val("#rt"));
    if (n !== ROOT && !validName(n)) throw new Error("Name: lowercase letters, digits and inner hyphens.");
    if (!t) throw new Error("Paste a contract id or a node URL.");
    await setRecord(n, t);
    minePage();
  });
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
}

// Inside the node's container the page is a sandboxed iframe: leaving it goes through the shell.
const goTo = (href: string) => (window.parent !== window ? parent.postMessage({ __freenet_shell__: true, type: "navigate", href }, "*") : void (location.href = href));

/** Viso sent the user back here with its proof (or a refusal). */
async function signInCallback(q: URLSearchParams) {
  app.innerHTML = `<h1>Viso</h1><p class="muted">Checking the proof…</p>`;
  let html: string;
  try { html = `<p>Signed in as the persona <code>${esc(personaName(await finishSignIn(q)))}</code>.</p>`; }
  catch (e) { html = `<p class="err">${esc(String((e as Error).message ?? e))}</p>`; }
  history.replaceState(null, "", `${location.pathname}#/mine`); // drop the one-time query
  app.innerHTML = `<h1>Viso</h1>${html}<p><a class="btn primary" href="#/mine">Go to My names</a></p>`;
}

// ---------------- how it works ----------------
function howPage() {
  app.innerHTML = `
    <h1>How it works</h1>
    <p>Freenet addresses look like <code>6s9q7nSCmPrHY85RfPjQpdHo7WTFabDCTtsJAzHXfuLN</code>. FreeNames lets you type <code>scobru</code> or <code>scobru/freetunes</code> instead.</p>
    <div class="card">
      <h2>1. Your identity is your Viso persona</h2>
      <p>You sign in with <b>Viso</b> once per node. Viso signs a short delegation: "this app key, kept by your node, may write for me in FreeNames". Every change carries that delegation and the app key's signature, and the contracts check both. Your names belong to the persona, not to the app key: if you lose your node, sign in again from another one. No key or seed is shared and there is nothing to back up here.</p>
    </div>
    <div class="card">
      <h2>2. Your zone: names under your persona</h2>
      <p>Your <b>zone</b> is a contract whose address comes from your persona key: it maps names to contract addresses. <code>@</code> is your main site, anything else a sub-name. Only your persona can authorize changes, so nobody can take these names from you. Anyone can reach them as <code>&lt;persona key&gt;/name</code>.</p>
    </div>
    <div class="card">
      <h2>3. Petnames: your own labels</h2>
      <p>A persona key is not something people remember. A <b>petname</b> is your private label for someone's key (<code>ivvor</code> → their key). It lives on your node, nobody else sees it, and it always wins over the registry, so nobody can redirect your petnames.</p>
    </div>
    <div class="card">
      <h2>4. The registry: short public names</h2>
      <p>The <b>registry</b> maps short names to keys for everyone. Claiming a name means signing it and spending a few seconds of computing (proof of work). Freenet has no global clock, so "first come, first served" cannot be checked. Instead:</p>
      <ul>
        <li>if the registry admin <b>pinned</b> the name, the pin decides (a pin can also reserve a name);</li>
        <li>otherwise the <b>strongest proof</b> wins. Taking a name costs as much work as its holder spent, and the holder can always add more.</li>
      </ul>
      <p class="muted">So registry names are convenient but not absolute. When it matters, share your key or a petname.</p>
    </div>
    <div class="card">
      <h2>5. Resolving a name</h2>
      <p><code>name/sub</code>: <code>name</code> is a key, your petname, or a registry name, in that order. That gives an owner key. Their zone gives the address of <code>sub</code> (or <code>@</code>), which your node opens.</p>
    </div>
    <div class="card">
      <h2>Limits</h2>
      <ul>
        <li>Nodes drop contracts nobody asks for: a name stays reachable while someone keeps it hosted.</li>
        <li>Whoever controls your node can write for your persona in FreeNames until you sign in elsewhere; delegations do not expire yet.</li>
        <li>Someone with more computing power can take an unpinned registry name.</li>
      </ul>
    </div>`;
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
