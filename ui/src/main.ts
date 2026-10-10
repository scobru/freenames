import "./style.css";
import {
  claimName, createIdentity, exportSecret, finishLink, loadPetnames, loadRegistry, loadZone, officialWhoiam, peekIdentity, personaName,
  pinNames, REGISTRY_ADMIN, replaceIdentity, resolve, savePetnames, setRecord, startLink, unlinkPersona, webUrl, zonePersona, type Identity,
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

// route: #/ resolve | #/go/<name> | #/mine | #/how | #/admin (not linked anywhere); ?whoiam=... is whoiam's callback
function route() {
  if (window.parent !== window) parent.postMessage({ __freenet_shell__: true, type: "hash", hash: location.hash || "#/" }, "*");
  const h = location.hash;
  document.querySelectorAll<HTMLElement>("[data-nav]").forEach((a) => a.toggleAttribute("aria-current", a.getAttribute("href") === (h || "#/")));
  const q = new URLSearchParams(location.search);
  if (q.has("whoiam")) return linkCallback(q);
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
    <p class="muted"><code>name</code> opens the site a name points to, <code>name/sub</code> one of its sub-names. Your petnames come first, then the public registry.</p>
    <form id="f" class="row"><input id="q" placeholder="scobru/freetunes" autocomplete="off" spellcheck="false" value="${esc(initial)}" /><button class="primary">Resolve</button></form>
    <div id="out"></div>`;
  const run = async (q: string) => {
    const out = $("#out");
    out.innerHTML = `<p class="muted">Looking up…</p>`;
    try {
      const r = await resolve(q);
      if (!r.owner) { out.innerHTML = `<p class="err">Nobody holds this name.</p>`; return; }
      const badge = r.persona ? ` · <span class="chip" title="whoiam persona ${esc(personaName(r.persona))}">whoiam ✓ ${esc(personaName(r.persona).slice(0, 8))}…</span>` : "";
      const who = `owner <code title="${r.owner}">${short(r.owner)}</code> (via ${r.via})${badge}`;
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
  app.innerHTML = `<h1>My names</h1><div id="box"><p class="muted">Connecting to the node and reading your key (up to about 10 s the first time)…</p></div>`;
  let me: Identity | null;
  try { me = await peekIdentity(); }
  catch (e) { $("#box").innerHTML = `<p class="err">Could not reach the node: ${esc(String((e as Error).message ?? e))}</p>`; return; }
  if (!me) {
    $("#box").innerHTML = `
      <p class="muted">Your names belong to a key kept by your node. Create one, or import a secret key you exported before.</p>
      <p><button id="new" class="primary">Create a key</button></p>
      <div class="card"><h2>Import</h2><div class="row"><input id="isk" type="password" placeholder="secret key (64 hex)" autocomplete="off" /><button id="imp">Import</button></div><p id="io"></p></div>`;
    act("#new", "#io", async () => { await createIdentity(); minePage(); });
    act("#imp", "#io", async () => { await replaceIdentity(val("#isk")); minePage(); });
    return;
  }
  const pk = me.pk;
  const loading = `<tr><td class="muted">Loading from the node (can take up to 30 s)…</td></tr>`;
  $("#box").innerHTML = `
    <div class="card">
      <h2>Key</h2>
      <p><code class="wrap">${pk}</code></p>
      <p class="muted"><small>Others can always reach your names as <code>${short(pk)}/name</code>, even without the registry.${me.persisted ? "" : " <b>This browser cannot keep the key: export it.</b>"}</small></p>
      <p><button id="exp">Show secret key</button> <span id="eo"></span></p>
    </div>
    <div class="card" id="wc"><h2>whoiam</h2><p class="muted">Loading…</p></div>
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
      <div class="row"><input id="pn" placeholder="name" autocomplete="off" /><input id="pk" placeholder="their key (64 hex)" autocomplete="off" /><button id="ps">Add</button></div>
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
    return zonePersona(zone, pk).then(drawWhoiam);
  }, (e) => {
    $("#zt").innerHTML = `<tr><td>${fail(e)}</td></tr>`;
    $("#wc").innerHTML = `<h2>whoiam</h2><p>${fail(e)}</p>`;
  });

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

/** Link a whoiam persona to your key: whoiam signs a proof, FreeNames never receives any secret. */
function drawWhoiam(persona: string | null) {
  const card = $("#wc");
  if (persona) {
    card.innerHTML = `<h2>whoiam</h2>
      <p>Linked to the persona <code>${esc(personaName(persona))}</code>. Everyone who resolves your names sees a whoiam ✓ badge.</p>
      <p><button id="wun" class="danger">Unlink</button> <span id="wo"></span></p>`;
    act("#wun", "#wo", async () => { await unlinkPersona(); minePage(); });
    return;
  }
  card.innerHTML = `<h2>whoiam</h2>
    <p class="muted">Show who stands behind your names: one of your <b>whoiam</b> personas signs that it knows this key. No key or seed is shared. whoiam opens, you pick a persona, you come back here.</p>
    <div class="row"><input id="wurl" value="${esc(officialWhoiam())}" spellcheck="false" autocomplete="off" /><button id="wgo" class="primary">Link a persona</button></div>
    <p id="wo"></p>`;
  act("#wgo", "#wo", async () => { goTo(await startLink(val("#wurl"))); return "Opening whoiam…"; });
}

/** whoiam sent the user back here with its proof (or a refusal). */
async function linkCallback(q: URLSearchParams) {
  app.innerHTML = `<h1>whoiam</h1><p class="muted">Checking the proof and publishing it in your zone…</p>`;
  let html: string;
  try { html = `<p>Linked to the persona <code>${esc(personaName(await finishLink(q)))}</code>.</p>`; }
  catch (e) { html = `<p class="err">${esc(String((e as Error).message ?? e))}</p>`; }
  history.replaceState(null, "", `${location.pathname}#/mine`); // drop the one-time query
  app.innerHTML = `<h1>whoiam</h1>${html}<p><a class="btn primary" href="#/mine">Back to My names</a></p>`;
}

// ---------------- how it works ----------------
function howPage() {
  app.innerHTML = `
    <h1>How it works</h1>
    <p>Freenet addresses look like <code>6s9q7nSCmPrHY85RfPjQpdHo7WTFabDCTtsJAzHXfuLN</code>. FreeNames lets you type <code>scobru</code> or <code>scobru/freetunes</code> instead.</p>
    <div class="card">
      <h2>1. Your zone: names under your key</h2>
      <p>Your key is created by your node and never leaves it. Your <b>zone</b> is a contract whose address comes from your key: it maps names to contract addresses. <code>@</code> is your main site, anything else a sub-name. Only you can sign changes, so nobody can take these names from you. Anyone can reach them as <code>&lt;your key&gt;/name</code>.</p>
    </div>
    <div class="card">
      <h2>2. Petnames: your own labels</h2>
      <p>A key is not something people remember. A <b>petname</b> is your private label for someone's key (<code>ivvor</code> → their key). It lives on your node, nobody else sees it, and it always wins over the registry, so nobody can redirect your petnames.</p>
    </div>
    <div class="card">
      <h2>3. The registry: short public names</h2>
      <p>The <b>registry</b> maps short names to keys for everyone. Claiming a name means signing it and spending a few seconds of computing (proof of work). Freenet has no global clock, so "first come, first served" cannot be checked. Instead:</p>
      <ul>
        <li>if the registry admin <b>pinned</b> the name, the pin decides (a pin can also reserve a name);</li>
        <li>otherwise the <b>strongest proof</b> wins. Taking a name costs as much work as its holder spent, and the holder can always add more.</li>
      </ul>
      <p class="muted">So registry names are convenient but not absolute. When it matters, share your key or a petname.</p>
    </div>
    <div class="card">
      <h2>4. Resolving a name</h2>
      <p><code>name/sub</code>: <code>name</code> is a key, your petname, or a registry name, in that order. That gives an owner key. Their zone gives the address of <code>sub</code> (or <code>@</code>), which your node opens.</p>
    </div>
    <div class="card">
      <h2>5. whoiam: who is behind a key</h2>
      <p>You can link a <b>whoiam</b> persona: whoiam signs that the persona knows your FreeNames key, and the proof is published in your zone. Whoever resolves your names checks it and sees a whoiam ✓ badge. No key or seed is shared.</p>
    </div>
    <div class="card">
      <h2>Limits</h2>
      <ul>
        <li>Nodes drop contracts nobody asks for: a name stays reachable while someone keeps it hosted.</li>
        <li>Losing your key means losing your names: export it from My names.</li>
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
