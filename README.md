# FreeNames

> **Experiment.** FreeNames is an experiment on [Freenet](https://freenet.org): human-readable names for Freenet contracts. Unfinished; may break or lose data.

Freenet addresses look like `6s9q7nSCmPrHY85RfPjQpdHo7WTFabDCTtsJAzHXfuLN`. FreeNames lets you type `scobru` or `scobru/freetunes` instead.

## The problem

A name system can be at most two of **global**, **secure** and **human-readable** (Zooko's triangle). Freenet has no global consensus and no shared clock, so "first come, first served" cannot be enforced: a contract merge must give the same result in any order, so any rule that picks between two claims can be gamed by whoever produces a "better" claim. FreeNames therefore uses three layers, from most to least secure:

| Layer | Form | Secure? | Global? |
| --- | --- | --- | --- |
| **Zone** | `<persona key>/name` | yes: only the persona authorizes writes | yes, but not readable |
| **Petname** | `alice/name` (your own label for a key) | yes | no: local to your node |
| **Registry** | `alice/name` (a short public name) | as far as the rules below go | yes |

Your identity is your [whoiam](https://github.com/skandragon/freenet-whoiam) persona (see *Identity* below).

Resolution: `first/sub` → `first` is a 64-hex persona key, else your petname, else the registry → the owner's zone → record `sub` (or `@`, the zone root, when there is no `/sub`) → contract id → `http://<node>/v1/contract/web/<id>/`.

## Design

| Part | What it holds | Address |
| --- | --- | --- |
| **Delegation** (`delegation/`) | Plain Rust library, no Freenet dependency: checks a whoiam delegation and returns the app key it authorizes. | — |
| **Zone** (`zone/`) | The names one persona publishes: name → contract id. Each record is signed by a delegated app key (`fnz2\|<persona>\|<name>\|<target>\|<ts>`) and carries its delegation. Newest record per name wins; an empty target is a tombstone. Up to 1000 records. | parameters = persona public key + app path |
| **Registry** (`registry/`) | Claims: name → persona, signed by a delegated app key (`fnc1\|<admin>\|<name>\|<persona>`), with its delegation and an 18-bit sha256 proof-of-work. Admin-signed pins (`fnp1\|<ts>\|name=persona,...`). | one shared instance (parameters = admin public key + app path) |
| **Identity delegate** (`identity/`) | The node's app key (disposable) and a small store (session, petnames). | one per calling web app |

### Identity: whoiam delegation

There is no FreeNames account and no key to back up. You sign in with whoiam once per node:

1. The node keeps a random **app key**. FreeNames opens whoiam's "sign in" flow with the challenge `wd1.<app key>.<nonce>`.
2. whoiam signs, with the persona you pick, `"whoiam-connect-v1" ‖ persona ‖ len ‖ return_base ‖ len ‖ challenge ‖ ts`. `return_base` is FreeNames' own address, so the signature means: *this app key may write for me in FreeNames*. That signature is the **delegation**.
3. Every write is signed by the app key and carries the delegation. The contracts check both, and that the delegation's path is the one in their parameters (`/v1/contract/web/<FreeNames id>/`), so a delegation made for another app is useless here.

The owner of zones and claims is the **persona**. A new node or a lost one is just another sign-in. The signature format is checked against whoiam's golden vector (`delegation/src/lib.rs`, `ui/src/whoiam.test.ts`).

This uses whoiam's connect flow for something it does not advertise: whoiam shows "sign in to <origin>", not "authorize this key". When whoiam ships its own cross-app delegation, FreeNames should switch to it.

### Who owns a registry name

1. If the admin pinned the name, the pin decides (`name=` with no owner reserves it).
2. Otherwise the **strongest proof** wins: the claim whose `sha256(message|nonce)` is lowest. Taking a name costs about as much work as its holder spent, and the holder can mine a stronger claim at any time.

The contract keeps the 3 strongest owners per name and the 5000 strongest claims overall. That is a union under a total order, so every merge order converges, and pins never delete claims (unpinning brings the strongest claim back).

Names are lowercase ASCII letters, digits and inner hyphens, 1 to 63 characters: no look-alike Unicode.

### Known limits

- **The registry is only as fair as proof-of-work.** Someone with more CPU can take an unpinned name. Pins fix that, but they make the admin a central authority for pinned names. Use zones or petnames when that matters.
- Zones and the registry are ordinary contracts: nodes drop contracts nobody asks for. A name stays reachable while someone keeps it hosted.
- Delegations do not expire and cannot be revoked yet (contracts have no clock): whoever controls a node you signed in from can keep writing for your persona in FreeNames.
- In `npm run dev` the app path is `/`, so dev zones and the dev registry are separate from the published ones, and whoiam sign-in only works on the published site (it must be on the same node).
- Not yet: revoking a delegation, delegation through other people's petnames (`ivvor.kate`), name expiry, anchoring claims to Bitcoin for admin-free global names.
- Untested against a live node. The contracts are covered by `cargo test`; the UI is type-checked, its name logic is unit-tested, and the resolve page was checked in a browser without a node.

## Development

Requirements: `rustup` with the `wasm32-unknown-unknown` target, `freenet` and `fdev`, Node 20+.

```bash
cargo test --release
cargo build --release --target wasm32-unknown-unknown -p freenames-zone -p freenames-registry -p freenames-identity
for n in zone registry identity; do cp target/wasm32-unknown-unknown/release/freenames_$n.wasm ui/src/$n.wasm; done

# isolated dev node on :7510
mkdir -p .devnode/config .devnode/data .devnode/log
freenet local local --ws-api-port 7510 --config-dir .devnode/config --data-dir .devnode/data --log-dir .devnode/log --disable-auto-update

cd ui && npm install && npm test && echo VITE_NODE=127.0.0.1:7510 > .env.local && npm run dev
```

The Rust and TypeScript sides share one claim-strength vector (`registry/src/lib.rs`, `ui/src/names.test.ts`).

### Registry admin

The admin public key is `REGISTRY_ADMIN` in `ui/src/lib.ts` (the same key as the FreeTunes directory admin; the signed messages are domain-separated). The admin page is `#/admin` (not linked anywhere). Changing the key or the registry code creates a new, empty registry.

### Publishing the site

```bash
cd ui && npm run build
fdev website init freenames
fdev website publish dist --key freenames     # later: fdev website update dist --key freenames
```

## License

MIT, see [LICENSE](LICENSE).
