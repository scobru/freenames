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
import { claimMsg, isKey, parseName, pinsMsg, resolveOwner, zoneMsg, type RegState, type Zone } from "./names";
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
export const getState = (instance: string) =>
  serial(() => retrying(async () => {
    const r = await (await api()).get(new GetRequest(fullKey(instance), false));
    if (r.key?.codePart()?.length === 32) keys.set(instance, r.key);
    return new Uint8Array(r.state);
  }));
const getJson = async <T>(instance: string) => JSON.parse(new TextDecoder().decode(await getState(instance))) as T;

async function sendDelta(instance: string, delta: object) {
  const d = new UpdateData(UpdateDataType.DeltaUpdate, new DeltaUpdate(bytes(JSON.stringify(delta))));
  await (await api()).update(new UpdateRequest(fullKey(instance), d));
}

// ---------------------------------------------------------------- identity delegate
// The signing key lives in the node (one per calling web app), so it survives sessions even inside the sandboxed
// container where the page has no storage. If the delegate is missing or silent, fall back to localStorage, then memory.
export interface Identity { pk: string; persisted: boolean; sign: (msg: string) => Promise<string> }

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

/** Where the signing key lives. Creating an identity is always an explicit step: nothing here makes one by itself. */
interface KeyStore {
  persisted: boolean;
  pk(): Promise<string | null>; // null when there is no identity yet
  create(sk: string): Promise<string>; // keeps the existing one, if any
  replace(sk: string): Promise<string>;
  exportSk(): Promise<string>;
  sign(msg: string): Promise<string>;
}

const delegateStore: KeyStore = {
  persisted: true,
  pk: async () => {
    try { return (await callDelegate({ op: "pubkey" })).pk as string; }
    catch (e) { if (/no identity/.test(String(e))) return null; throw e; }
  },
  create: async (sk) => (await callDelegate({ op: "init", sk })).pk,
  replace: async (sk) => (await callDelegate({ op: "replace", sk })).pk,
  exportSk: async () => (await callDelegate({ op: "export" })).sk,
  sign: async (msg) => (await callDelegate({ op: "sign", msg })).sig,
};

let memKey: string | null = null;
let lsWorks = true;
const readKey = () => { try { return localStorage.getItem("fn-sk"); } catch { lsWorks = false; return memKey; } };
const writeKey = (h: string) => { memKey = h; try { localStorage.setItem("fn-sk", h); } catch { lsWorks = false; } };
const localStore: KeyStore = {
  get persisted() { return lsWorks; },
  pk: async () => { const h = readKey(); return h ? hex(await ed.getPublicKeyAsync(unhex(h))) : null; },
  create: async (sk) => { if (!readKey()) writeKey(sk); return hex(await ed.getPublicKeyAsync(unhex(readKey()!))); },
  replace: async (sk) => { writeKey(sk); return hex(await ed.getPublicKeyAsync(unhex(sk))); },
  exportSk: async () => { const h = readKey(); if (!h) throw new Error("no identity"); return h; },
  sign: async (msg) => hex(await ed.signAsync(enc.encode(msg), unhex(readKey()!))),
};

const keyStore = async () => ((await hasDelegate()) ? delegateStore : localStore);
const asIdentity = (s: KeyStore, pk: string): Identity => ({ pk, persisted: s.persisted, sign: (m) => s.sign(m) });
const newSecret = () => hex(ed.utils.randomPrivateKey());

/** The identity, if one exists. Never creates one: listeners and visitors do not need a key. */
export async function peekIdentity(): Promise<Identity | null> {
  const s = await keyStore(), pk = await s.pk();
  return pk ? asIdentity(s, pk) : null;
}

/** The identity, or an error telling the user to create one. For everything that signs. */
export async function requireIdentity(): Promise<Identity> {
  const me = await peekIdentity();
  if (!me) throw new Error("Create an identity first (Identity in the menu).");
  return me;
}

/** Create an identity with a fresh key. If one exists already it is kept. */
export async function createIdentity(): Promise<Identity> {
  const s = await keyStore();
  return asIdentity(s, await s.create(newSecret()));
}


/** Replace the identity with `sk` (hex): for restoring a backup. The old key is gone unless it was exported. */
export async function replaceIdentity(sk: string): Promise<Identity> {
  if (!/^[0-9a-f]{64}$/.test(sk)) throw new Error("A secret key is 64 hex characters.");
  const s = await keyStore();
  return asIdentity(s, await s.replace(sk));
}

/** The secret key, for a backup the user asked for. */
export const exportSecret = async () => (await keyStore()).exportSk();

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

/** Find a nonce so that sha256(`<msg>|<nonce>`) starts with `bits` zero bits (a moment of CPU). */
async function mine(msg: string, bits: number): Promise<number> {
  let nonce = 0;
  while (zeroBits(sha256(enc.encode(`${msg}|${nonce}`))) < bits) {
    if (++nonce % 20000 === 0) await new Promise((r) => setTimeout(r)); // let the page breathe while mining
  }
  return nonce;
}


// ---------------------------------------------------------------- registry (see registry/src/lib.rs)
let regId: Promise<string> | undefined;
const registryId = () => (regId ??= keyOf(registryWasm, unhex(REGISTRY_ADMIN)).then((k) => k.encode()));
const EMPTY_REG: RegState = { claims: {}, pins: { ts: 0, map: {}, sig: "" } };

/** Load the registry. The first visitor on a node creates it (empty). */
export async function loadRegistry(): Promise<RegState> {
  const id = await registryId();
  try { return await getJson<RegState>(id); }
  catch {
    await putContract(registryWasm, unhex(REGISTRY_ADMIN), enc.encode(JSON.stringify(EMPTY_REG)));
    return getJson<RegState>(id);
  }
}

/** Claim a short name for your key: sign it and mine the proof-of-work (a few seconds). */
export async function claimName(name: string) {
  const me = await requireIdentity();
  const msg = claimMsg(REGISTRY_ADMIN, name, me.pk);
  const sig = await me.sign(msg), nonce = await mine(msg, POW_BITS);
  await loadRegistry(); // makes sure it exists and caches its full key for the update
  await sendDelta(await registryId(), { claims: { [name]: { [me.pk]: { nonce, sig } } } });
}

/** Admin only: replace the pins (name -> owner key, "" reserves the name). */
export async function pinNames(adminSecretHex: string, map: Record<string, string>) {
  const ts = Date.now();
  const sig = hex(await ed.signAsync(enc.encode(pinsMsg({ ts, map })), unhex(adminSecretHex)));
  await loadRegistry();
  await sendDelta(await registryId(), { pins: { ts, map, sig } });
}

// ---------------------------------------------------------------- zones (see zone/src/lib.rs)
const zoneId = (pk: string) => keyOf(zoneWasm, unhex(pk)).then((k) => k.encode());

/** A key's zone, or null if it never published one. */
export async function loadZone(pk: string): Promise<Zone | null> {
  try { return await getJson<Zone>(await zoneId(pk)); } catch { return null; }
}

/** Point one of your names at a contract (empty target removes it). The first record creates your zone. */
export async function setRecord(name: string, target: string) {
  const me = await requireIdentity();
  const ts = Date.now(), rec = { target, ts, sig: await me.sign(zoneMsg(me.pk, name, target, ts)) };
  const records = { [name]: rec };
  if (await loadZone(me.pk)) await sendDelta(await zoneId(me.pk), { records });
  else await putContract(zoneWasm, unhex(me.pk), enc.encode(JSON.stringify({ records })));
}

// ---------------------------------------------------------------- petnames and resolution
export const loadPetnames = async (): Promise<Record<string, string>> => JSON.parse((await storeGet("petnames")) ?? "{}");
export const savePetnames = (p: Record<string, string>) => storePut("petnames", JSON.stringify(p));

export interface Resolution { owner: string | null; via: "key" | "petname" | "registry"; sub: string; target: string | null }

/** `name[/sub]`: your petnames first, then the registry; then the owner's zone. */
export async function resolve(input: string): Promise<Resolution> {
  const p = parseName(input);
  if (!p) throw new Error("Not a name: use name, name/sub or a 64-hex key.");
  let owner: string | null, via: Resolution["via"];
  const pets = await loadPetnames();
  if (isKey(p.first)) [owner, via] = [p.first, "key"];
  else if (pets[p.first]) [owner, via] = [pets[p.first], "petname"];
  else [owner, via] = [resolveOwner(REGISTRY_ADMIN, await loadRegistry(), p.first), "registry"];
  const target = owner ? (await loadZone(owner))?.records[p.sub]?.target || null : null;
  return { owner, via, sub: p.sub, target };
}

/** Where the node serves a contract's web app (in dev the page is on Vite, the node elsewhere). */
export const webUrl = (id: string) =>
  `${import.meta.env.DEV ? `http://${import.meta.env.VITE_NODE ?? "127.0.0.1:7509"}` : `${location.protocol}//${location.host}`}/v1/contract/web/${id}/`;
