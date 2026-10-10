import { test } from "node:test";
import assert from "node:assert/strict";
import { contractId, parseName, pinsMsg, resolveOwner, strength, validName } from "./names.ts";

const A = "aa".repeat(32), O = "bb".repeat(32), P = "cc".repeat(32);

test("claim strength matches the contract (same vector as registry/src/lib.rs)", () => {
  assert.equal(strength(A, "x", O, 7), "d62d6f096a13690dea0ee38885ab0645ff8b124129f1958a15075ecf78ff3125");
});

test("pins message is sorted by name", () => {
  assert.equal(pinsMsg({ ts: 3, map: { music: O, admin: "" } }), `fnp1|3|admin=,music=${O}`);
});

test("resolve: pin first, else the lowest hash", () => {
  const claims = { x: { [O]: { nonce: 7, sig: "" }, [P]: { nonce: 1, sig: "" } } };
  const best = strength(A, "x", O, 7) < strength(A, "x", P, 1) ? O : P;
  assert.equal(resolveOwner(A, { claims, pins: { ts: 0, map: {}, sig: "" } }, "x"), best);
  assert.equal(resolveOwner(A, { claims, pins: { ts: 1, map: { x: P }, sig: "" } }, "x"), P);
  assert.equal(resolveOwner(A, { claims, pins: { ts: 1, map: { x: "" }, sig: "" } }, "x"), null);
  assert.equal(resolveOwner(A, { claims, pins: { ts: 0, map: {}, sig: "" } }, "y"), null);
});

test("names and inputs", () => {
  assert.ok(validName("my-site-2") && !validName("-a") && !validName("A") && !validName("a".repeat(64)));
  assert.deepEqual(parseName(" Scobru/FreeTunes "), { first: "scobru", sub: "freetunes" });
  assert.deepEqual(parseName("fn:scobru"), { first: "scobru", sub: "@" });
  assert.deepEqual(parseName(`${O}/music`), { first: O, sub: "music" });
  assert.equal(parseName("a/b/c"), null);
  assert.equal(parseName("a.b"), null);
  const id = "7jKW1CQj7RxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxA";
  assert.equal(contractId(`http://127.0.0.1:7509/v1/contract/web/${id}/?f=x`), id);
  assert.equal(contractId(id), id);
  assert.equal(contractId("not an id"), null);
});
