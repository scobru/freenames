# Using FreeNames from your app

How another Freenet app can turn human-readable names like `scobru`, `scobru/freetunes`, `fn:name`, or `freenet:name/sub` into a contract ID, link to FreeNames, and let its users publish names.

Reference implementations:
- **[Radica](https://github.com/scobru/radica)** (`ui/src/freenames.ts`): full-featured client integration with BLAKE3 code hash shortcuts, in-flight deduplication, multi-level caching, and non-blocking asynchronous UI hydration.
- **[FH](https://github.com/scobru/FH)** (`src/names.ts`, `src/net.ts`): lightweight reference implementation with bundled WASM files.

Read the [README](../README.md) first for the core model:
- **Registry** (short global name → persona public key)
- **Zone** (persona's records: name → contract ID)
- **Petnames** (private labels, local to the FreeNames delegate on that node)

---

## 1. Constants & Contract Addressing

| What | Value |
| --- | --- |
| FreeNames site | `CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE` |
| App path (`FREENAMES_PATH`) | `/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/` |
| Registry admin (`REGISTRY_ADMIN`) | `4498bd4c2ab992afa152bc9b968e246cf70dc4fa5a670b23c33e73b8516ce9f3` |
| Registry WASM BLAKE3 code hash | `79eba61ac4e4020f5b7823fd0f88db508909a82753e9bb3a8d1e91c37cb40476` |
| Zone WASM BLAKE3 code hash | `115ee6ed3d24f999d6765cfa1bdae0d75b41c80062dbb3274f4db84bc7510d15` |
| Contract code | `ui/src/registry.wasm`, `ui/src/zone.wasm` in this repo |

### Contract Key Derivation

A Freenet contract's instance ID is derived as:
$$\text{instance} = \text{BLAKE3}(\text{code\_hash} \parallel \text{parameters})$$
where $\text{code\_hash} = \text{BLAKE3}(\text{WASM code})$.

Both FreeNames contracts require **a 32-byte key followed by FreeNames' app path (`FREENAMES_PATH`)** as their parameters:
- **Registry:** `hexToBytes(REGISTRY_ADMIN)` (32 bytes) $\parallel$ `enc.encode(FREENAMES_PATH)`
- **Zone:** `hexToBytes(persona_pubkey)` (32 bytes) $\parallel$ `enc.encode(FREENAMES_PATH)`

> [!IMPORTANT]
> Always use `FREENAMES_PATH` in the parameters, **never** your own app's path. FreeNames contracts and whoiam delegations are domain-separated by path.

You have two choices for building contract keys:
1. **Code Hash Shortcut (Recommended, as in Radica):** Use the pre-computed BLAKE3 code hashes above. You don't need to bundle or load WASM files in your frontend bundle.
2. **Bundling WASM:** Copy `ui/src/registry.wasm` and `ui/src/zone.wasm` into your project and compute their BLAKE3 hashes at runtime. If FreeNames releases new contract code, copy the new WASMs or update the code hashes.

---

## 2. Name & URI Syntax

FreeNames identifiers appear in several forms:
- `name` or `name/@` — Zone root `@` of `name`.
- `name/sub` — Sub-record `sub` within `name`'s zone.
- `fn:name` or `fn:name/sub` — Explicit FreeNames scheme.
- `freenet:name/sub` or `freenet://name/sub` — Standard Freenet URI.
- `freenet:<64-hex persona key>/sub` — Zone lookup directly on a persona key (bypassing the registry).
- Subpaths & query/fragment (e.g. `freenet:scobru/fh/album/1#intro`) — Resolves the root target and preserves the subpath (`/album/1#intro`).

### Validation rules:
- Names (`name`, `sub`) must be lowercase ASCII letters, digits, and inner hyphens: `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`.
- Persona keys are 64 hexadecimal characters (`^[0-9a-f]{64}$`).
- Target contract IDs are Base58 strings (typically 20–64 characters).

---

## 3. Resolving a Name (Read-Only)

Resolution follows these steps:

1. **Parse URI**: Separate `first`, `sub` (default `@`), and any remaining `subpath`.
2. **Resolve Owner of `first`**:
   - If `first` is a 64-hex persona key, `owner = first`.
   - Otherwise, fetch the Registry contract state (`registryKey()`).
   - If `pins.map[first]` exists:
     - If non-empty: owner is `pins.map[first]`.
     - If empty string `""`: the name is reserved by the admin (no owner).
   - Otherwise, search `claims[first]`: find the owner whose claim has the **lowest** SHA-256 proof hash:
     $$\text{SHA256}(\text{"fnc1|" } \Vert \text{ REGISTRY\_ADMIN } \Vert \text{ name } \Vert \text{ owner } \Vert \text{ nonce})$$
     (compared in lexicographical hex byte order).
3. **Resolve Target**:
   - Fetch the Zone contract for `owner` (`zoneKey(owner)`).
   - Look up `records[sub].target`. An empty string indicates the record was deleted (tombstone).
4. **Form URL**:
   - Full URL: `http://<node-origin>/v1/contract/web/<target>/<subpath>`

> [!NOTE]
> Petnames are stored in FreeNames' local identity delegate on the user's node. External apps cannot read them, so resolutions through third-party apps proceed through public registry claims, pins, or direct persona keys.

---

## 4. Reference TypeScript Implementation

Here is a complete, production-ready module following Radica's patterns (using `@noble/hashes` and `@freenetorg/freenet-stdlib`):

```ts
import { sha256 } from "@noble/hashes/sha2.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { ContractKey } from "@freenetorg/freenet-stdlib";

export const FREENAMES_KEY = "CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE";
const FREENAMES_PATH = `/v1/contract/web/${FREENAMES_KEY}/`;
const REGISTRY_ADMIN = "4498bd4c2ab992afa152bc9b968e246cf70dc4fa5a670b23c33e73b8516ce9f3";

const REGISTRY_CODE = "79eba61ac4e4020f5b7823fd0f88db508909a82753e9bb3a8d1e91c37cb40476";
const ZONE_CODE = "115ee6ed3d24f999d6765cfa1bdae0d75b41c80062dbb3274f4db84bc7510d15";

const enc = new TextEncoder();
const dec = new TextDecoder();

// Derive ContractKey using BLAKE3: BLAKE3(code_hash || parameters)
export const keyOf = (codeHash: string, params: Uint8Array): ContractKey => {
  const code = hexToBytes(codeHash);
  const buf = new Uint8Array(code.length + params.length);
  buf.set(code, 0);
  buf.set(params, code.length);
  return new ContractKey(blake3(buf), code);
};

export const registryKey = (): ContractKey =>
  keyOf(REGISTRY_CODE, new Uint8Array([...hexToBytes(REGISTRY_ADMIN), ...enc.encode(FREENAMES_PATH)]));

export const zoneKey = (personaHex: string): ContractKey =>
  keyOf(ZONE_CODE, new Uint8Array([...hexToBytes(personaHex), ...enc.encode(FREENAMES_PATH)]));

export const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const isKey = (s: string) => /^[0-9a-f]{64}$/.test(s);
export const ID_RE = /^[1-9A-HJ-NP-Za-km-z]{20,64}$/;

export interface FreenameUri {
  first: string;
  sub: string;
  subpath: string;
  canonical: string;
}

export function parseFreenameUri(input: string, allowBare = false): FreenameUri | null {
  const trimmed = input.trim();
  const m = allowBare
    ? /^(?:freenet:(?:\/\/)?:?|fn:)?(.+)$/i.exec(trimmed)
    : /^(?:freenet:(?:\/\/)?:?|fn:)(.+)$/i.exec(trimmed);
  if (!m) return null;

  const raw = m[1];
  const hashIdx = raw.search(/[?#]/);
  const pathPart = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  const queryPart = hashIdx >= 0 ? raw.slice(hashIdx) : "";

  const segments = pathPart.split("/").filter((s) => s.length > 0);
  if (segments.length === 0) return null;

  const rawFirst = segments[0];
  if (/[A-Z]/.test(rawFirst)) return null; // lowercase only

  const first = rawFirst.toLowerCase();
  if (!(isKey(first) || NAME_RE.test(first))) return null;
  if (first.length >= 32 && !isKey(first)) return null;

  const isFnScheme = trimmed.toLowerCase().startsWith("fn:") || (allowBare && !trimmed.toLowerCase().startsWith("freenet:"));

  if (segments.length === 1) {
    if (!isFnScheme) return null;
    return { first, sub: "@", subpath: queryPart, canonical: first };
  }

  const sub = segments[1].toLowerCase();
  if (sub !== "@" && !NAME_RE.test(sub)) return null;

  const extraPath = segments.slice(2).join("/");
  const fullSubpath = (extraPath ? `/${extraPath}` : "") + queryPart;

  return {
    first,
    sub,
    subpath: fullSubpath,
    canonical: sub === "@" ? first : `${first}/${sub}`,
  };
}

export interface RegState {
  claims: Record<string, Record<string, { nonce: number }>>;
  pins: { map: Record<string, string> };
}

export function ownerOf(s: RegState, name: string): string | null {
  if (name in s.pins.map) return s.pins.map[name] || null;
  let best: { o: string; h: string } | null = null;
  for (const [o, c] of Object.entries(s.claims[name] ?? {})) {
    const h = bytesToHex(sha256(enc.encode(`fnc1|${REGISTRY_ADMIN}|${name}|${o}|${c.nonce}`)));
    if (!best || h < best.h) best = { o, h };
  }
  return best?.o ?? null;
}

// In-flight deduplication & in-memory caches
const resolvedCache = new Map<string, { owner: string | null; target: string | null }>();
const inflightResolutions = new Map<string, Promise<{ owner: string | null; target: string | null }>>();
const zoneCache = new Map<string, Promise<Uint8Array | null>>();

export async function resolveName(
  input: string,
  fetchRaw: (key: ContractKey) => Promise<Uint8Array | null>,
  allowBare = true
): Promise<{ owner: string | null; target: string | null; canonical: string; subpath: string } | null> {
  const uri = parseFreenameUri(input, allowBare);
  if (!uri) return null;

  const hit = resolvedCache.get(uri.canonical);
  if (hit) return { ...hit, canonical: uri.canonical, subpath: uri.subpath };

  let p = inflightResolutions.get(uri.canonical);
  if (!p) {
    p = (async () => {
      let owner: string | null = null;
      if (isKey(uri.first)) {
        owner = uri.first;
      } else {
        const rawReg = await fetchRaw(registryKey()).catch(() => null);
        if (!rawReg) return { owner: null, target: null };
        try {
          const regState = JSON.parse(dec.decode(rawReg)) as RegState;
          owner = ownerOf(regState, uri.first);
        } catch {
          return { owner: null, target: null };
        }
      }
      if (!owner) {
        const res = { owner: null, target: null };
        resolvedCache.set(uri.canonical, res);
        return res;
      }

      let zP = zoneCache.get(owner);
      if (!zP) {
        zP = fetchRaw(zoneKey(owner)).catch(() => null);
        zoneCache.set(owner, zP);
      }
      const rawZone = await zP;
      let target: string | null = null;
      if (rawZone) {
        try {
          const zData = JSON.parse(dec.decode(rawZone));
          const recTarget = zData?.records?.[uri.sub]?.target;
          if (typeof recTarget === "string") {
            const m = recTarget.match(/(?:\/v[12]\/contract\/(?:web\/)?|^)([1-9A-HJ-NP-Za-km-z]{20,64})/);
            target = m ? m[1] : null;
          }
        } catch {}
      }

      const res = { owner, target };
      resolvedCache.set(uri.canonical, res);
      return res;
    })();
    inflightResolutions.set(uri.canonical, p);
  }

  const res = await p;
  return { ...res, canonical: uri.canonical, subpath: uri.subpath };
}
```

---

## 5. UI Integration & Asynchronous Hydration

Network fetches on Freenet take time, and missing contracts may timeout. Radica uses a two-phase rendering strategy to ensure snappy user interfaces:

1. **Initial Fast Render**:
   - Detect FreeNames links in text/captions.
   - Render an anchor tag pointing to the FreeNames web fallback URL:
     ```ts
     export const nameHref = (origin: string, name: string) =>
       `${origin}/v1/contract/web/${FREENAMES_KEY}/#/go/${encodeURIComponent(name)}`;
     ```
   - Mark the element with data attributes:
     ```html
     <a class="fn-link" data-freenames="scobru/freetunes" href="http://<node>/v1/contract/web/.../#/go/scobru%2Ffreetunes">scobru/freetunes</a>
     ```
2. **Asynchronous Hydration**:
   - Once the DOM container is mounted, call a hydration helper (e.g., `fillFreenames(container)`).
   - When `resolveName` returns a target ID, update `link.href` to:
     `${origin}/v1/contract/web/${target}/${subpath}`
   - Mark `data-resolved="true"` so it is not re-processed.

---

## 6. Linking to FreeNames

- **Open FreeNames' lookup page for a name**:
  `http://<node>/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/#/go/<name>` (URL-encode `/` as `%2F`).
- **Navigating within the Freenet Web Container**:
  Inside Freenet's sandboxed iframe container, navigate via the host shell:
  ```ts
  parent.postMessage({ __freenet_shell__: true, type: "navigate", href }, "*");
  ```

---

## 7. Letting Users Publish Names

Claims and zone records must be signed by an app key **delegated for FreeNames' app path** (`whoiam-delegation` checks the path in the certificate).

A delegation made for your app is invalid for FreeNames, so **your app cannot write names directly for the user**.
Instead, redirect the user to FreeNames' **My Names** page:
`http://<node>/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/#/mine`
and display the contract ID of what they created in your app so they can paste it as the target.

---

## 8. Rust Integration

In Rust, the `freenames-zone` and `freenames-registry` crates expose the state types and `zone::resolve`. Depend on them with `default-features = false` so their contract entry points are not compiled into your binary:

```toml
[dependencies]
freenames-zone = { path = "../zone", default-features = false }
freenames-registry = { path = "../registry", default-features = false }
```

---

## 9. Checklist

- [ ] **Parameters:** `key || FREENAMES_PATH` (never your app's own path).
- [ ] **Contract code:** Use either the verified BLAKE3 code hashes (`REGISTRY_CODE`, `ZONE_CODE`) or copy the exact published WASM files.
- [ ] **Proof of Work:** Smallest hash of `fnc1|<REGISTRY_ADMIN>|<name>|<owner>|<nonce>` wins; admin pins override.
- [ ] **Timeouts:** Wrap all `GetRequest` calls with a timeout (30–45 s); treat timeout or not-found as `null`.
- [ ] **Deduplication:** Cache in-flight promises to avoid duplicate parallel requests for the same name.
- [ ] **Sanitization:** Pass all user input through `parseFreenameUri` before issuing network requests.
