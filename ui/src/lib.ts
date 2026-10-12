import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FreenetWsApi, ContractKey, ContractContainer, ContractType, WasmContractV1, PutRequest, GetRequest,
  UpdateRequest, UpdateData, UpdateDataType, DeltaUpdate, DelegateRequest, type DelegateResponse, type ResponseHandler,
} from "@freenetorg/freenet-stdlib";
import { ApplicationMessageT, ContractCodeT } from "@freenetorg/freenet-stdlib/common";
import {
  ApplicationMessagesT, ClientRequestT, ClientRequestType, DelegateCodeT, DelegateContainerT, DelegateKeyT,
  DelegateRequestType, DelegateType, InboundDelegateMsgT, InboundDelegateMsgType, RegisterDelegateT,
  RelatedContractsT, WasmDelegateV1T,
} from "@freenetorg/freenet-stdlib/client-request";
import { claimMsg, isKey, parseName, pinsMsg, resolveOwner, ROOT, strength, zoneMsg, type RegState, type Zone } from "./names";
import { connectMessage, verifyProof } from "./whoiam";
export { personaName } from "./whoiam";
import zoneWasm from "./zone.wasm?url";
import registryWasm from "./registry.wasm?url";
import identityWasm from "./identity.wasm?url";

const { bytesToHex: hex, hexToBytes: unhex } = ed.etc;
const enc = new TextEncoder();
const bytes = (s: string) => Array.from(enc.encode(s));

// The registry address depends on this admin key (its parameter): changing it creates a new, empty registry.
// Same key as the FreeTunes directory admin; the signed messages are domain-separated (fnp1 vs ftb1).
export const REGISTRY_ADMIN = "4498bd4c2ab992afa152bc9b968e246cf70dc4fa5a670b23c33e73b8516ce9f3";
const POW_BITS = 18; // must match registry/src/lib.rs

// ---------------------------------------------------------------- node connection
interface Waiter { resolve(r: DelegateResponse): void; reject(e: Error): void }
const delegateWaiters: Waiter[] = [];


let apiP: Promise<FreenetWsApi> | undefined;
export function api(): Promise<FreenetWsApi> {
  return (apiP ??= new Promise((resolve, reject) => {
    const url = new URL(import.meta.env.DEV
      ? `ws://${import.meta.env.VITE_NODE ?? "127.0.0.1:7509"}/v1/contract/command`
      : `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/v1/contract/command`); // the shell only proxies its own origin
    const h: ResponseHandler = {
      onContractPut() {}, onContractGet() {}, onContractUpdate() {}, onContractUpdateNotification() {},
      onContractNotFound: () => console.warn("contract not found"),
      onDelegateResponse: (r) => delegateWaiters.shift()?.resolve(r),
      onErr: (e) => console.error(e.cause),
      onOpen: () => resolve(a),
      onClose: () => {
        apiP = undefined;
        delegateWaiters.splice(0).forEach((w) => w.reject(new Error("socket closed"))); // their replies will never come
        reject(new Error("socket closed"));
      },
    };
    const a = new FreenetWsApi(url, h, "");
  }));
}

// The socket can drop right after the page opens (for example while the shell re-authenticates):
// retry a couple of times instead of failing the first load.
async function retrying<T>(f: () => Promise<T>, tries = 3): Promise<T> {
  for (let i = 1; ; i++) {
    try { return await f(); }
    catch (e) {
      if (i >= tries || !/closed/i.test(String(e))) throw e;
      console.warn(`connection dropped, retrying (${i}/${tries - 1}):`, e);
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
}

// get() responses are matched by arrival order: serialize them
let chain: Promise<unknown> = Promise.resolve();
const serial = <T>(f: () => Promise<T>): Promise<T> => {
  const p = chain.then(f);
  chain = p.catch(() => {});
  return p;
};

// ---------------------------------------------------------------- contracts
const codes = new Map<string, Promise<{ code: Uint8Array; codeHash: Uint8Array }>>();
const codeOf = (url: string) => {
  let p = codes.get(url);
  if (!p) codes.set(url, (p = fetch(url).then(async (r) => { const code = new Uint8Array(await r.arrayBuffer()); return { code, codeHash: blake3(code) }; })));
  return p;
};

/** Contract key. Instance id = blake3(blake3(wasm) || params), as in freenet-stdlib. */
async function keyOf(wasm: string, params: Uint8Array) {
  const { codeHash } = await codeOf(wasm);
  return new ContractKey(blake3(new Uint8Array([...codeHash, ...params])), codeHash);
}

async function putContract(wasm: string, params: Uint8Array, state: Uint8Array) {
  const { code, codeHash } = await codeOf(wasm);
  const key = await keyOf(wasm, params);
  const contract = new WasmContractV1(new ContractCodeT(Array.from(code), Array.from(codeHash)), Array.from(params), key);
  await (await api()).put(new PutRequest(new ContractContainer(ContractType.WasmContractV1, contract), Array.from(state), new RelatedContractsT()));
  return key.encode();
}

// full keys (instance + code hash) learned from get(); UPDATE needs the code hash
const keys = new Map<string, ContractKey>();
const fullKey = (instance: string) => keys.get(instance) ?? ContractKey.fromInstanceId(instance);

/** Raw state of a contract. */
export const getState = (instance: string, subscribe = false) =>
  serial(() => retrying(async () => {
    const r = await (await api()).get(new GetRequest(fullKey(instance), false, subscribe));
    if (r.key?.codePart()?.length === 32) keys.set(instance, r.key);
    return new Uint8Array(r.state);
  }));
const getJson = async <T>(instance: string, subscribe = false) => JSON.parse(new TextDecoder().decode(await getState(instance, subscribe))) as T;

async function sendDelta(instance: string, delta: object) {
  const d = new UpdateData(UpdateDataType.DeltaUpdate, new DeltaUpdate(bytes(JSON.stringify(delta))));
  await (await api()).update(new UpdateRequest(fullKey(instance), d));
}

// ---------------------------------------------------------------- identity delegate
// The signing key lives in the node (one per calling web app), so it survives sessions even inside the sandboxed
// container where the page has no storage. If the delegate is missing or silent, fall back to localStorage, then memory.

let delegateKey: DelegateKeyT | undefined;
let delegateChain: Promise<unknown> = Promise.resolve();

// Every delegate request, registration included, gets one DelegateResponse with no request id: go one at a time.
function sendDelegate(req: DelegateRequest, timeoutMs = 8000): Promise<DelegateResponse> {
  const run = async () => {
    let waiter!: Waiter;
    const reply = new Promise<DelegateResponse>((resolve, reject) => {
      waiter = { resolve, reject };
      delegateWaiters.push(waiter);
      setTimeout(() => {
        const i = delegateWaiters.indexOf(waiter);
        if (i >= 0) { delegateWaiters.splice(i, 1); reject(new Error("delegate timeout")); }
      }, timeoutMs);
    });
    const a = (await api()) as unknown as { sendRequest(r: ClientRequestT): void }; // the SDK has no delegate method yet
    a.sendRequest(new ClientRequestT(ClientRequestType.DelegateRequest, req));
    return reply;
  };
  const p = delegateChain.then(run);
  delegateChain = p.catch(() => {});
  return p;
}

/** Hand a delegate's wasm to the node (idempotent) and return its key: blake3(blake3(wasm)) for empty parameters. */
async function registerWasmDelegate(wasmUrl: string, expectHash?: string): Promise<DelegateKeyT> {
  const code = new Uint8Array(await (await fetch(wasmUrl)).arrayBuffer());
  const codeHash = blake3(code);
  if (expectHash && hex(codeHash) !== expectHash) throw new Error("unexpected delegate code");
  const key = new DelegateKeyT(Array.from(blake3(codeHash)), Array.from(codeHash));
  const wasm = new WasmDelegateV1T([], new DelegateCodeT(Array.from(code), Array.from(codeHash)), key);
  const container = new DelegateContainerT(DelegateType.WasmDelegateV1, wasm);
  // the node ignores cipher and nonce (secrets use a node-side key) but still checks their sizes
  await sendDelegate(new DelegateRequest(DelegateRequestType.RegisterDelegate, new RegisterDelegateT(container, new Array(32).fill(0), new Array(24).fill(0))));
  return key;
}

/** One application message to a registered delegate; resolves with the payload of its reply. */
async function messageDelegate(key: DelegateKeyT, payload: Uint8Array, timeoutMs?: number): Promise<Uint8Array> {
  const msg = new InboundDelegateMsgT(InboundDelegateMsgType.common_ApplicationMessage, new ApplicationMessageT(Array.from(payload), [], false));
  const r = await sendDelegate(new DelegateRequest(DelegateRequestType.ApplicationMessages, new ApplicationMessagesT(key, [], [msg])), timeoutMs);
  // duck-typed: bundlers can duplicate the SDK classes, which breaks instanceof
  const m = r.values.map((v) => v.inbound).find((x) => Array.isArray((x as ApplicationMessageT | null)?.payload)) as ApplicationMessageT | undefined;
  if (!m) throw new Error(`empty delegate reply (the node sent: ${r.values.map((v) => v.inboundType).join(", ") || "nothing"})`);
  return new Uint8Array(m.payload);
}

async function registerDelegate() {
  delegateKey = await registerWasmDelegate(identityWasm);
}

// every delegate operation is safe to repeat (init keeps the first key, the rest are reads, signatures and overwrites)
const callDelegate = (payload: object) => retrying(() => callDelegateOnce(payload));

async function callDelegateOnce(payload: object): Promise<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const out = JSON.parse(new TextDecoder().decode(await messageDelegate(delegateKey!, enc.encode(JSON.stringify(payload)))));
  if (out.err) throw new Error(out.err);
  return out;
}

// The delegate is optional: if it is missing or silent we fall back to localStorage, then to memory.
let delegateReady: Promise<boolean> | undefined;
const hasDelegate = () =>
  (delegateReady ??= retrying(registerDelegate).then(() => true, (e) => {
    console.warn("identity delegate unavailable, using the local key store:", e);
    return false;
  }));

/** Where the app key lives. It is disposable: whoiam delegates it, and a lost one is replaced by signing in again. */
interface KeyStore {
  pk(): Promise<string | null>;
  create(sk: string): Promise<string>; // keeps the existing one, if any
  sign(msg: string): Promise<string>;
}

const delegateStore: KeyStore = {
  pk: async () => {
    try { return (await callDelegate({ op: "pubkey" })).pk as string; }
    catch (e) { if (/no identity/.test(String(e))) return null; throw e; }
  },
  create: async (sk) => (await callDelegate({ op: "init", sk })).pk,
  sign: async (msg) => (await callDelegate({ op: "sign", msg })).sig,
};

let memKey: string | null = null;
const readKey = () => { try { return localStorage.getItem("fn-sk"); } catch { return memKey; } };
const writeKey = (h: string) => { memKey = h; try { localStorage.setItem("fn-sk", h); } catch { /* sandbox: memory only */ } };
const localStore: KeyStore = {
  pk: async () => { const h = readKey(); return h ? hex(await ed.getPublicKeyAsync(unhex(h))) : null; },
  create: async (sk) => { if (!readKey()) writeKey(sk); return hex(await ed.getPublicKeyAsync(unhex(readKey()!))); },
  sign: async (msg) => hex(await ed.signAsync(enc.encode(msg), unhex(readKey()!))),
};

const keyStore = async () => ((await hasDelegate()) ? delegateStore : localStore);
/** The app key (hex), created on first use. */
const appKey = async () => { const s = await keyStore(); return (await s.pk()) ?? s.create(hex(ed.utils.randomPrivateKey())); };

// small per-app store (petnames): the delegate when available, else localStorage, else memory
const mem = new Map<string, string>();
export async function storeGet(key: string): Promise<string | null> {
  const d = await hasDelegate();
  let local: string | null = null;
  try { local = localStorage.getItem(`fn-${key}`); } catch { /* sandbox: no storage */ }
  if (d) { try { return (await callDelegate({ op: "get", key })).value ?? local; } catch { /* use local */ } }
  return local ?? mem.get(key) ?? null;
}
export async function storePut(key: string, value: string) {
  mem.set(key, value);
  try { localStorage.setItem(`fn-${key}`, value); } catch { /* sandbox: no storage */ }
  if (await hasDelegate()) { try { await callDelegate({ op: "put", key, value }); } catch (e) { console.warn("delegate store failed:", e); } }
}
const zeroBits = (h: Uint8Array) => {
  let n = 0;
  for (const b of h) { n += Math.clz32(b) - 24; if (b) break; }
  return n;
};

/** Find a nonce so that sha256(`<msg>|<nonce>`) starts with `bits` zero bits and, if given, is below `beat` (hex). */
async function mine(msg: string, bits: number, beat = ""): Promise<number> {
  for (let nonce = 0; ; nonce++) {
    const h = sha256(enc.encode(`${msg}|${nonce}`));
    if (zeroBits(h) >= bits && (!beat || hex(h) < beat)) return nonce;
    if (nonce % 20000 === 19999) await new Promise((r) => setTimeout(r)); // let the page breathe while mining
  }
}


// The app's own path: delegations and contract parameters are bound to it (in dev, "/").
const APP_PATH = location.pathname;
const withApp = (keyHex: string) => new Uint8Array([...unhex(keyHex), ...enc.encode(APP_PATH)]);

// ---------------------------------------------------------------- session: a whoiam persona and its delegation
// whoiam signs `wd1.<app key>.<nonce>` for this app's address: "this app key acts for me here"
// (see delegation/src/lib.rs). The persona is the identity; the app key only signs on its behalf.
export interface Cert { base: string; challenge: string; ts: number; sig: string }
export interface Session { persona: string; cert: Cert; sign: (msg: string) => Promise<string> }

/** The signed-in persona, if its delegation still holds for this node's app key. */
export async function session(): Promise<Session | null> {
  const raw = await storeGet("session");
  if (!raw) return null;
  const { persona, cert } = JSON.parse(raw) as { persona: string; cert: Cert };
  const s = await keyStore(), k = await s.pk();
  if (!k || cert.challenge.split(".")[1] !== k) return null; // the app key changed: sign in again
  return { persona, cert, sign: (m) => s.sign(m) };
}

async function requireSession(): Promise<Session> {
  const s = await session();
  if (!s) throw new Error("Sign in first (My names).");
  return s;
}

/** Forget the sign-in, and the persona key if it was made here (the user was told to save it first). */
export const signOut = async () => { await storePut("session", ""); await storePut("persona-key", ""); };

/** The official Viso web contract; any other Viso site on this node can be used instead. */
export const VISO_KEY = "GzHy3jnEtj26EoGqMsBpoawcY378hK9kp91rTcNYiAac";
export const WHOIAM_KEY = VISO_KEY;
export const officialViso = () => `${location.protocol}//${location.host}/v1/contract/web/${VISO_KEY}/`;
export const officialWhoiam = officialViso;
const LINK_MAX_AGE_MS = 10 * 60 * 1000;
/** Our own address without query or hash: Viso binds its proof to it. */
const linkBase = () => `${location.protocol}//${location.host}${APP_PATH}`;

/** Where to send the user to sign in. Remembers the one-time challenge in the delegate store. */
export async function startSignIn(visoUrl: string): Promise<string> {
  const u = new URL(visoUrl);
  if (u.host !== location.host || !/^\/v[12]\/contract\/web\/[^/]+\/?$/.test(u.pathname)) {
    throw new Error("Paste the address of your Viso site on this node (it starts with the same host as this page).");
  }
  const challenge = `wd1.${await appKey()}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`;
  await storePut("signin-pending", challenge);
  return `${u.origin}${u.pathname}?connect=v1&challenge=${challenge}&return=${encodeURIComponent(linkBase())}`;
}

/** Handle Viso's callback: check challenge, freshness and signature, then keep the delegation. */
export async function finishSignIn(q: URLSearchParams): Promise<string> {
  if (q.get("viso") === "denied" || q.get("whoiam") === "denied") throw new Error("You chose not to share a persona.");
  const pending = await storeGet("signin-pending");
  await storePut("signin-pending", ""); // one use: burn it whatever happens next
  const persona = q.get("pk") ?? "";
  const cert: Cert = { base: linkBase(), challenge: q.get("challenge") ?? "", ts: Number(q.get("ts")), sig: q.get("sig") ?? "" };
  if (!pending || cert.challenge !== pending) throw new Error("This sign-in is unknown or was already used. Start again from My names.");
  if (!Number.isFinite(cert.ts) || Math.abs(Date.now() - cert.ts) > LINK_MAX_AGE_MS) throw new Error("The proof is too old or its clock is off. Start again.");
  if (!(await verifyProof({ ...cert, pk: persona }))) throw new Error("Viso signature does not verify.");
  await storePut("session", JSON.stringify({ persona, cert }));
  return persona;
}

/** A persona made here instead of in Viso: a new key (or an imported one, hex) signs the same proof Viso would. */
export async function createLocalIdentity(secretHex?: string): Promise<string> {
  const sk = secretHex?.replace(/\s/g, "").toLowerCase() || hex(ed.utils.randomPrivateKey());
  if (!/^[0-9a-f]{64}$/.test(sk)) throw new Error("The key must be 64 hexadecimal characters.");
  const persona = hex(await ed.getPublicKeyAsync(sk));
  const cert: Cert = { base: linkBase(), challenge: `wd1.${await appKey()}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, ts: Date.now(), sig: "" };
  cert.sig = hex(await ed.signAsync(connectMessage(unhex(persona), cert.base, cert.challenge, cert.ts), sk));
  await storePut("persona-key", sk);
  await storePut("session", JSON.stringify({ persona, cert }));
  return persona;
}

/** The secret key of a persona made here (hex), for the user to back up; null for a Viso persona. */
export const localIdentityKey = async () => (await storeGet("persona-key")) || null;

// ---------------------------------------------------------------- registry (see registry/src/lib.rs)
let regId: Promise<string> | undefined;
const registryId = () => (regId ??= keyOf(registryWasm, withApp(REGISTRY_ADMIN)).then((k) => k.encode()));
const EMPTY_REG: RegState = { claims: {}, pins: { ts: 0, map: {}, sig: "" } };

/** Load the registry. The first visitor on a node creates it (empty). Subscribing keeps the node's copy fresh. */
export async function loadRegistry(): Promise<RegState> {
  const id = await registryId();
  try { return await getJson<RegState>(id, true); }
  catch {
    await putContract(registryWasm, withApp(REGISTRY_ADMIN), enc.encode(JSON.stringify(EMPTY_REG)));
    return getJson<RegState>(id);
  }
}

/** Claim a short name for your persona: sign it and mine the proof-of-work (a few seconds). */
export async function claimName(name: string) {
  const me = await requireSession();
  const msg = claimMsg(REGISTRY_ADMIN, name, me.persona);
  const reg = await loadRegistry(); // also makes sure it exists and caches its full key for the update
  if (name in reg.pins.map) throw new Error("The registry admin pinned this name: no proof of work can take it.");
  // to take a held name, the proof must be stronger (lower) than every other owner's
  const beat = Object.entries(reg.claims[name] ?? {}).filter(([o]) => o !== me.persona)
    .map(([o, c]) => strength(REGISTRY_ADMIN, name, o, c.nonce)).sort()[0];
  const sig = await me.sign(msg), nonce = await mine(msg, POW_BITS, beat);
  const prev = await myClaims(me.persona);
  await storePut(`claims-${me.persona}`, JSON.stringify({ ...prev, [name]: { nonce, sig, cert: me.cert } }));
  await sendClaims(me.persona, [name]);
}

/** Claims this persona made from this node, kept so they can be sent again if the registry copy lost them. */
const myClaims = async (persona: string): Promise<Record<string, object>> => JSON.parse((await storeGet(`claims-${persona}`)) || "{}");

async function sendClaims(persona: string, names: string[]) {
  const all = await myClaims(persona);
  const claims = Object.fromEntries(names.filter((n) => all[n]).map((n) => [n, { [persona]: all[n] }]));
  await sendDelta(await registryId(), { claims });
}

/** Send again the claims of ours the registry does not show; returns their names. */
export async function resendMissingClaims(persona: string, reg: RegState): Promise<string[]> {
  const missing = Object.keys(await myClaims(persona)).filter((n) => !reg.claims[n]?.[persona]);
  if (missing.length) await sendClaims(persona, missing);
  return missing;
}

/** Admin only: replace the pins (name -> persona key, "" reserves the name). */
export async function pinNames(adminSecretHex: string, map: Record<string, string>) {
  const ts = Date.now();
  const sig = hex(await ed.signAsync(enc.encode(pinsMsg({ ts, map })), unhex(adminSecretHex)));
  await loadRegistry();
  await sendDelta(await registryId(), { pins: { ts, map, sig } });
}

// ---------------------------------------------------------------- zones (see zone/src/lib.rs)
const zoneId = (persona: string) => keyOf(zoneWasm, withApp(persona)).then((k) => k.encode());

/** A persona's zone, or null if the node cannot find one (a missing contract can also just time out). */
export async function loadZone(persona: string): Promise<Zone | null> {
  try { return await getJson<Zone>(await zoneId(persona)); }
  catch (e) { if (/not found|timeout/i.test(String(e))) return null; throw e; }
}

/** Point one of your names at a contract (empty target removes it). The first record creates your zone. */
export async function setRecord(name: string, target: string) {
  const me = await requireSession();
  const ts = Date.now(), rec = { target, ts, sig: await me.sign(zoneMsg(me.persona, name, target, ts)), cert: me.cert };
  const records = { [name]: rec };
  if (await loadZone(me.persona)) await sendDelta(await zoneId(me.persona), { records });
  else await putContract(zoneWasm, withApp(me.persona), enc.encode(JSON.stringify({ records })));
}

// ---------------------------------------------------------------- petnames and resolution
export const loadPetnames = async (): Promise<Record<string, string>> => JSON.parse((await storeGet("petnames")) || "{}");
export const savePetnames = (p: Record<string, string>) => storePut("petnames", JSON.stringify(p));

export interface Resolution { owner: string | null; via: "key" | "petname" | "registry"; sub: string; target: string | null }

/** `name[/sub]`: your petnames first, then the registry; then the owner's zone. */
export async function resolve(input: string): Promise<Resolution> {
  const p = parseName(input);
  if (!p) throw new Error("Not a name: use name, name/sub or a 64-hex persona key.");
  let owner: string | null, via: Resolution["via"];
  const pets = await loadPetnames();
  if (isKey(p.first)) [owner, via] = [p.first, "key"];
  else if (pets[p.first]) [owner, via] = [pets[p.first], "petname"];
  else [owner, via] = [resolveOwner(REGISTRY_ADMIN, await loadRegistry(), p.first), "registry"];
  const target = owner ? (await loadZone(owner))?.records[p.sub]?.target || null : null;
  return { owner, via, sub: p.sub, target };
}

export interface Hit { name: string; target: string; owner: string }
const MAX_SEARCH_OWNERS = 100;

/** Names containing `q` (lowercase; "" = all): petnames and registry names, with their owners' sub-names. Hits arrive as zones load; stops after `max`. */
export async function search(q: string, onHit: (h: Hit) => void, max = Infinity) {
  let n = 0;
  const pets = await loadPetnames(), reg = await loadRegistry();
  const labels = new Map<string, string>(); // label -> owner; petnames win, as in `resolve`
  for (const n of [...Object.keys(reg.claims), ...Object.keys(reg.pins.map)]) {
    const o = resolveOwner(REGISTRY_ADMIN, reg, n);
    if (o) labels.set(n, o);
  }
  for (const [n, o] of Object.entries(pets)) labels.set(n, o);
  const zones = new Map<string, Promise<Zone | null>>(); // one load per owner, even with several labels
  // shortcut: only the first MAX_SEARCH_OWNERS labels are searched; add an index contract if the registry grows past that
  for (const [label, owner] of [...labels].slice(0, MAX_SEARCH_OWNERS)) {
    if (!zones.has(owner)) zones.set(owner, loadZone(owner).catch(() => null));
    for (const [sub, r] of Object.entries((await zones.get(owner)!)?.records ?? {})) {
      const name = sub === ROOT ? label : `${label}/${sub}`;
      if (r.target && name.includes(q)) { onHit({ name, target: r.target, owner }); if (++n >= max) return; }
    }
  }
}

/** Where the node serves a contract's web app (in dev the page is on Vite, the node elsewhere). */
export const webUrl = (id: string) =>
  `${import.meta.env.DEV ? `http://${import.meta.env.VITE_NODE ?? "127.0.0.1:7509"}` : `${location.protocol}//${location.host}`}/v1/contract/web/${id}/`;
