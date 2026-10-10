// Pure name logic, shared with zone/src/lib.rs and registry/src/lib.rs (same messages, same rules).
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export interface Claim { nonce: number; sig: string }
export interface Pins { ts: number; map: Record<string, string>; sig: string }
export interface RegState { claims: Record<string, Record<string, Claim>>; pins: Pins }
export interface ZoneRecord { target: string; ts: number; sig: string }
export interface Zone { records: Record<string, ZoneRecord>; persona?: { proof: string; ts: number; sig: string } }

export const ROOT = "@";
const enc = new TextEncoder();

/** Lowercase ASCII letters, digits and inner hyphens, 1 to 63 long. */
export const validName = (n: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(n);
export const isKey = (s: string) => /^[0-9a-f]{64}$/.test(s);

export const claimMsg = (admin: string, name: string, owner: string) => `fnc1|${admin}|${name}|${owner}`;
export const zoneMsg = (owner: string, name: string, target: string, ts: number) => `fnz1|${owner}|${name}|${target}|${ts}`;
export const personaMsg = (owner: string, proof: string, ts: number) => `fnw1|${owner}|${proof}|${ts}`;
export const pinsMsg = (p: Pick<Pins, "ts" | "map">) =>
  `fnp1|${p.ts}|${Object.keys(p.map).sort().map((n) => `${n}=${p.map[n]}`).join(",")}`;

/** Proof hash of a claim, hex: lower is stronger (hex order = byte order). */
export const strength = (admin: string, name: string, owner: string, nonce: number) =>
  bytesToHex(sha256(enc.encode(`${claimMsg(admin, name, owner)}|${nonce}`)));

/** The owner of a registry name: the admin's pin if any ("" = reserved), else the strongest claim. */
export function resolveOwner(admin: string, s: RegState, name: string): string | null {
  if (name in s.pins.map) return s.pins.map[name] || null;
  let best: { o: string; h: string } | null = null;
  for (const [o, c] of Object.entries(s.claims[name] ?? {})) {
    const h = strength(admin, name, o, c.nonce);
    if (!best || h < best.h) best = { o, h };
  }
  return best?.o ?? null;
}

/** `name`, `name/sub`, `<64 hex key>` or `<key>/sub`. The part after the slash defaults to the zone root. */
export function parseName(input: string): { first: string; sub: string } | null {
  const [first, sub = ROOT, ...rest] = input.trim().toLowerCase().replace(/^fn:/, "").split("/");
  if (rest.length || !(isKey(first) || validName(first)) || !(sub === ROOT || validName(sub))) return null;
  return { first, sub };
}

/** A contract id from a bare id or a node URL (`.../v1/contract/web/<id>/...`). */
export function contractId(input: string): string | null {
  const s = input.trim();
  const m = s.match(/\/v1\/contract\/(?:web\/)?([1-9A-HJ-NP-Za-km-z]{32,64})/);
  const id = m ? m[1] : s;
  return /^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(id) ? id : null;
}
