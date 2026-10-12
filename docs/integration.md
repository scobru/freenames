# Using FreeNames from your app

How another Freenet app can turn a name like `scobru` or `scobru/freetunes` into a contract id, link to FreeNames, and let its users publish names. [FH](https://github.com/scobru/FH) does all of this; its code is the reference (`src/names.ts`, `src/net.ts`).

Read the README first for the model: **registry** (short global name → persona), **zone** (persona's records: name → contract id), **petnames** (private labels, local to FreeNames).

## 1. Constants

| What | Value |
| --- | --- |
| FreeNames site | `CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE` |
| App path (`FREENAMES_PATH`) | `/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/` |
| Registry admin (`REGISTRY_ADMIN`) | `4498bd4c2ab992afa152bc9b968e246cf70dc4fa5a670b23c33e73b8516ce9f3` |
| Contract code | `ui/src/registry.wasm`, `ui/src/zone.wasm` from this repo |

A contract's address is `blake3(blake3(wasm) || parameters)`. Both contracts take **a key followed by FreeNames' app path** as parameters:

- registry: `REGISTRY_ADMIN` (32 bytes) || `FREENAMES_PATH`
- zone of a persona: persona public key (32 bytes) || `FREENAMES_PATH`

So you need the **same wasm files FreeNames publishes**. Copy `registry.wasm` and `zone.wasm` into your app; if FreeNames ships new contract code, copy them again. With a different wasm the address is different and every lookup finds nothing.

## 2. Resolving a name (read-only)

Rules, the same as FreeNames' own resolve page:

1. `name` means `name/@` (`@` is the zone's root). `fn:` prefixes are allowed. Names are lowercase ASCII letters, digits and inner hyphens, 1 to 63 characters. The first part can also be a 64-hex persona key.
2. **Owner of `name`**: a 64-hex key is its own owner. Otherwise read the registry: if `pins.map` has the name, the pin decides (`""` = reserved, no owner). Otherwise the owner is the claim with the **lowest** `sha256("fnc1|<REGISTRY_ADMIN>|<name>|<owner>|<nonce>")` (hex order = byte order).
3. **Target**: read the owner's zone; the answer is `records[sub].target`, a contract instance id (base58). An empty target was removed.
4. Open it at `http://<node>/v1/contract/web/<target>/`.

Petnames live in FreeNames' own delegate store: other apps cannot read them, so names resolve through the registry or a persona key only.

TypeScript, as in FH (`@noble/hashes`, `@freenetorg/freenet-stdlib`; `contract()` builds the key, `getJson()` does a `GetRequest` and parses the JSON state, returning `null` when the node does not answer):

```ts
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import zoneWasm from "./fn-zone.wasm?url";          // FreeNames' ui/src/zone.wasm
import registryWasm from "./fn-registry.wasm?url";  // FreeNames' ui/src/registry.wasm

const FREENAMES_PATH = "/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/";
const REGISTRY_ADMIN = "4498bd4c2ab992afa152bc9b968e246cf70dc4fa5a670b23c33e73b8516ce9f3";
const enc = new TextEncoder();
const validName = (n: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(n);
const isKey = (s: string) => /^[0-9a-f]{64}$/.test(s);

export function parseName(input: string) {
  const [first, sub = "@", ...rest] = input.trim().toLowerCase().replace(/^fn:/, "").split("/");
  if (rest.length || !(isKey(first) || validName(first)) || !(sub === "@" || validName(sub))) return null;
  return { first, sub };
}

function resolveOwner(s: { claims: Record<string, Record<string, { nonce: number }>>; pins: { map: Record<string, string> } }, name: string) {
  if (name in s.pins.map) return s.pins.map[name] || null;
  let best: { o: string; h: string } | null = null;
  for (const [o, c] of Object.entries(s.claims[name] ?? {})) {
    const h = bytesToHex(sha256(enc.encode(`fnc1|${REGISTRY_ADMIN}|${name}|${o}|${c.nonce}`)));
    if (!best || h < best.h) best = { o, h };
  }
  return best?.o ?? null;
}

const withApp = (keyHex: string) => new Uint8Array([...hexToBytes(keyHex), ...enc.encode(FREENAMES_PATH)]);

/** The contract id a name points to, or null. */
export async function resolveName(input: string): Promise<string | null> {
  const p = parseName(input);
  if (!p) return null;
  let owner: string | null = p.first;
  if (!isKey(p.first)) {
    const reg = await getJson<any>(await contract(registryWasm, withApp(REGISTRY_ADMIN)));
    owner = reg && resolveOwner(reg, p.first);
  }
  if (!owner) return null;
  const zone = await getJson<any>(await contract(zoneWasm, withApp(owner)));
  return zone?.records[p.sub]?.target || null;
}
```

`contract()` and `getJson()` are a few lines each over the SDK: see FH's `src/store.ts`. A contract nobody asks for can be dropped by the network, and a `Get` for a missing contract can hang: put a timeout on it (FH waits 30 s) and treat it as "not found".

In Rust, the `freenames-zone` and `freenames-registry` crates expose the state types and `zone::resolve`; depend on them with `default-features = false` so their contract entry point is not compiled into your crate.

The node serving the state is untrusted. The registry and zone contracts validate every record when the state is stored, so a node that runs them honestly gives you valid records; if you need more, check each record's delegation and signature yourself (messages in the README, `whoiam-delegation` for the delegation).

## 3. Linking to FreeNames

- Open FreeNames' lookup for a name: `http://<node>/v1/contract/web/CDC7PTxNxfaNnJ3RJs8UrNHTScpT2NTujhvUiwirVejE/#/go/<name>` (URL-encode `/`).
- Inside the Freenet web container, leave your page through the shell: `parent.postMessage({ __freenet_shell__: true, type: "navigate", href }, "*")`.

## 4. Letting users publish names

Claims and zone records must be signed by an app key **delegated for FreeNames' app path** (`whoiam-delegation` checks the path in the certificate). A delegation made for your app does not work here, so your app cannot write names for the user. Send the user to FreeNames' **My names** page (`#/mine`) instead, and tell them what to point at: your app's contract id, or the id of what they created in it.

## 5. Checklist

- [ ] Same `registry.wasm` and `zone.wasm` as the published FreeNames.
- [ ] Parameters = key || `FREENAMES_PATH`, not your own app path.
- [ ] Lowest proof hash wins; pins override; `""` pin = reserved.
- [ ] Timeouts on `Get`; "not found" is a normal answer.
- [ ] Untrusted input: names from users go through `parseName` before any lookup.
