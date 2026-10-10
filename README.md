# FreeNames

> **Experiment.** FreeNames is an experiment on [Freenet](https://freenet.org): human-readable names for Freenet contracts. Unfinished; may break or lose data.

Freenet addresses look like `6s9q7nSCmPrHY85RfPjQpdHo7WTFabDCTtsJAzHXfuLN`. FreeNames lets you type `scobru` or `scobru/freetunes` instead.

## The problem

A name system can be at most two of **global**, **secure** and **human-readable** (Zooko's triangle). Freenet has no global consensus and no shared clock, so "first come, first served" cannot be enforced: a contract merge must give the same result in any order, so any rule that picks between two claims can be gamed by whoever produces a "better" claim. FreeNames therefore uses three layers, from most to least secure:

| Layer | Form | Secure? | Global? |
| --- | --- | --- | --- |
| **Zone** | `<key>/name` | yes: only the key's owner writes it | yes, but not readable |
| **Petname** | `alice/name` (your own label for a key) | yes | no: local to your node |
| **Registry** | `alice/name` (a short public name) | as far as the rules below go | yes |

Resolution: `first/sub` → `first` is a 64-hex key, else your petname, else the registry → the owner's zone → record `sub` (or `@`, the zone root, when there is no `/sub`) → contract id → `http://<node>/v1/contract/web/<id>/`.

## Design

| Contract | What it holds | Address |
| --- | --- | --- |
| **Zone** (`zone/`) | The names one key publishes: name → contract id, each record signed by the owner (`fnz1\|<owner>\|<name>\|<target>\|<ts>`). Newest record per name wins; an empty target is a tombstone. Up to 1000 records. Optionally a whoiam proof, signed by the owner (`fnw1\|<owner>\|<proof>\|<ts>`). | parameters = owner public key, so anyone who knows the key finds the zone |
| **Registry** (`registry/`) | Claims: name → owner key, signed by the owner (`fnc1\|<admin>\|<name>\|<owner>`) with an 18-bit sha256 proof-of-work. Admin-signed pins (`fnp1\|<ts>\|name=owner,...`). | one shared instance (its parameter is the admin public key) |
| **Identity delegate** (`identity/`) | Your signing key and a small store (petnames). Same delegate as FreeTunes. | one per calling web app |

### Who owns a registry name

1. If the admin pinned the name, the pin decides (`name=` with no owner reserves it).
2. Otherwise the **strongest proof** wins: the claim whose `sha256(message|nonce)` is lowest. Taking a name costs about as much work as its holder spent, and the holder can mine a stronger claim at any time.

The contract keeps the 3 strongest owners per name and the 5000 strongest claims overall. That is a union under a total order, so every merge order converges, and pins never delete claims (unpinning brings the strongest claim back).

Names are lowercase ASCII letters, digits and inner hyphens, 1 to 63 characters: no look-alike Unicode.

### whoiam

[whoiam](https://github.com/skandragon/freenet-whoiam) personas can vouch for a FreeNames key with whoiam's "sign in with whoiam" flow, as in [FreeTunes](https://github.com/scobru/freetunes): FreeNames sends a one-time challenge `<nonce>.<your key>`, whoiam signs it with the persona you pick, and FreeNames publishes the proof in your zone. The contract only checks your signature on it; whoever resolves your names verifies the proof and shows a "whoiam ✓" badge. No whoiam key or seed is ever shared. The signature format is checked against whoiam's golden vector (`ui/src/whoiam.test.ts`).

### Known limits

- **The registry is only as fair as proof-of-work.** Someone with more CPU can take an unpinned name. Pins fix that, but they make the admin a central authority for pinned names. Use zones or petnames when that matters.
- Zones and the registry are ordinary contracts: nodes drop contracts nobody asks for. A name stays reachable while someone keeps it hosted.
- Losing your key means losing your zone and your claims. Export it (My names → Show secret key).
- Not yet: delegation through other people's petnames (`ivvor.kate`), name expiry, anchoring claims to Bitcoin for admin-free global names.
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
