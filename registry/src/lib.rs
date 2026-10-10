//! Registry: short global names. One shared instance; parameters = admin ed25519 pubkey (32 bytes).
//! A claim binds a name to an owner key: it is signed by the owner and carries a proof-of-work. Several
//! owners can claim the same name. The admin's signed pins decide when present (an empty owner reserves
//! the name); otherwise the strongest proof (lowest hash) wins, so taking a name costs as much work as
//! its holder spent, and the holder can always add more. The name then resolves to the owner's zone.
//! Merging keeps, per name, the strongest claims of the strongest owners: a union under a total order,
//! so every merge order converges. State is JSON.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const POW_BITS: u32 = 18;
pub const PER_NAME: usize = 3;
pub const MAX_CLAIMS: usize = 5000;
const MAX_PINS: usize = 10_000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Claim {
    pub nonce: u64, // sha256(`<signed message>|<nonce>`) must start with POW_BITS zero bits
    pub sig: String, // hex, by the owner over `fnc1|<admin>|<name>|<owner>`
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Pins {
    pub ts: u64,
    pub map: BTreeMap<String, String>, // name -> owner pubkey hex, "" = reserved
    pub sig: String, // hex, by the admin over `fnp1|<ts>|<name>=<owner>,...` (sorted by name)
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RegState {
    pub claims: BTreeMap<String, BTreeMap<String, Claim>>, // name -> owner -> claim
    pub pins: Pins,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Summary {
    pub claims: BTreeMap<String, BTreeMap<String, u64>>, // name -> owner -> nonce
    pub pins_ts: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Delta {
    #[serde(default)]
    pub claims: BTreeMap<String, BTreeMap<String, Claim>>,
    #[serde(default)]
    pub pins: Option<Pins>,
}

type R<T> = Result<T, String>;

// key, verify and valid_name are the same as in zone/src/lib.rs
fn key(hexstr: &str) -> R<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hexstr)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes")?;
    VerifyingKey::from_bytes(&b).map_err(|e| e.to_string())
}

fn verify(k: &VerifyingKey, msg: &[u8], sig_hex: &str) -> R<()> {
    let sig = Signature::from_slice(&hex::decode(sig_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    k.verify(msg, &sig).map_err(|_| "bad signature".to_string())
}

pub fn valid_name(n: &str) -> bool {
    (1..=63).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !n.starts_with('-')
        && !n.ends_with('-')
}

fn claim_msg(admin: &str, name: &str, owner: &str) -> String {
    format!("fnc1|{admin}|{name}|{owner}")
}

/// Proof hash of a claim: lower is stronger.
pub fn strength(admin: &str, name: &str, owner: &str, c: &Claim) -> [u8; 32] {
    Sha256::digest(format!("{}|{}", claim_msg(admin, name, owner), c.nonce).as_bytes()).into()
}

fn zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

fn check_claim(admin: &str, name: &str, owner: &str, c: &Claim) -> R<()> {
    if !valid_name(name) {
        return Err("bad name".into());
    }
    verify(&key(owner)?, claim_msg(admin, name, owner).as_bytes(), &c.sig)?;
    if zero_bits(&strength(admin, name, owner, c)) < POW_BITS {
        return Err("insufficient proof of work".into());
    }
    Ok(())
}

pub fn pins_msg(p: &Pins) -> String {
    let list: Vec<String> = p.map.iter().map(|(n, o)| format!("{n}={o}")).collect();
    format!("fnp1|{}|{}", p.ts, list.join(","))
}

fn check_pins(admin: &str, p: &Pins) -> R<()> {
    if *p == Pins::default() {
        return Ok(()); // initial empty state
    }
    if p.map.len() > MAX_PINS || !p.map.iter().all(|(n, o)| valid_name(n) && (o.is_empty() || key(o).is_ok())) {
        return Err("bad pins".into());
    }
    verify(&key(admin)?, pins_msg(p).as_bytes(), &p.sig)
}

/// Keep the strongest `PER_NAME` owners per name and the strongest `MAX_CLAIMS` claims overall.
fn prune(admin: &str, s: &mut RegState) {
    let mut all: Vec<([u8; 32], String, String)> = s
        .claims
        .iter()
        .flat_map(|(n, m)| m.iter().map(move |(o, c)| (strength(admin, n, o, c), n.clone(), o.clone())))
        .collect();
    all.sort();
    let mut per: BTreeMap<String, usize> = BTreeMap::new();
    let mut kept = 0;
    for (_, n, o) in all {
        let c = per.entry(n.clone()).or_default();
        if *c < PER_NAME && kept < MAX_CLAIMS {
            *c += 1;
            kept += 1;
        } else if let Some(m) = s.claims.get_mut(&n) {
            m.remove(&o);
        }
    }
    s.claims.retain(|_, m| !m.is_empty());
}

pub fn validate(admin: &str, s: &RegState) -> R<()> {
    check_pins(admin, &s.pins)?;
    if s.claims.values().map(BTreeMap::len).sum::<usize>() > MAX_CLAIMS || s.claims.values().any(|m| m.len() > PER_NAME) {
        return Err("state out of bounds".into());
    }
    s.claims.iter().try_for_each(|(n, m)| m.iter().try_for_each(|(o, c)| check_claim(admin, n, o, c)))
}

pub fn apply(admin: &str, s: &mut RegState, d: Delta) -> R<()> {
    if let Some(p) = d.pins {
        if p.ts > s.pins.ts {
            check_pins(admin, &p)?;
            s.pins = p;
        }
    }
    for (name, m) in d.claims {
        for (owner, c) in m {
            let have = s.claims.get(&name).and_then(|m| m.get(&owner));
            if have.is_some_and(|h| strength(admin, &name, &owner, h) <= strength(admin, &name, &owner, &c)) {
                continue; // not stronger than what we hold for this owner
            }
            check_claim(admin, &name, &owner, &c)?;
            s.claims.entry(name.clone()).or_default().insert(owner, c);
        }
    }
    prune(admin, s);
    Ok(())
}

/// The owner a name belongs to: the pin if there is one, otherwise the strongest claim.
pub fn resolve<'a>(admin: &str, s: &'a RegState, name: &str) -> Option<&'a str> {
    if let Some(o) = s.pins.map.get(name) {
        return Some(o.as_str()).filter(|o| !o.is_empty());
    }
    let m = s.claims.get(name)?;
    m.iter().min_by_key(|(o, c)| strength(admin, name, o, c)).map(|(o, _)| o.as_str())
}

pub fn summarize(s: &RegState) -> Summary {
    Summary {
        claims: s
            .claims
            .iter()
            .map(|(n, m)| (n.clone(), m.iter().map(|(o, c)| (o.clone(), c.nonce)).collect()))
            .collect(),
        pins_ts: s.pins.ts,
    }
}

pub fn delta(s: &RegState, sum: &Summary) -> Delta {
    let mut claims: BTreeMap<String, BTreeMap<String, Claim>> = BTreeMap::new();
    for (n, m) in &s.claims {
        for (o, c) in m {
            if sum.claims.get(n).and_then(|m| m.get(o)) != Some(&c.nonce) {
                claims.entry(n.clone()).or_default().insert(o.clone(), c.clone());
            }
        }
    }
    Delta { claims, pins: (s.pins.ts > sum.pins_ts).then(|| s.pins.clone()) }
}

// ---- Freenet glue ----

fn admin(p: &Parameters) -> String {
    hex::encode(p.as_ref())
}

fn de<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T, ContractError> {
    serde_json::from_slice(b).map_err(|e| ContractError::Deser(e.to_string()))
}

/// Empty bytes (e.g. subscribe with no summary) mean "nothing known yet".
fn de_or_default<T: for<'a> Deserialize<'a> + Default>(b: &[u8]) -> Result<T, ContractError> {
    if b.is_empty() { Ok(T::default()) } else { de(b) }
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(v).map_err(|e| ContractError::Deser(e.to_string()))
}

struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let s: RegState = de_or_default(state.as_ref())?;
        Ok(match validate(&admin(&parameters), &s) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let admin = admin(&parameters);
        let mut s: RegState = de_or_default(state.as_ref())?;
        for u in data {
            let d: Delta = match u {
                UpdateData::State(st) => {
                    let o: RegState = de(st.as_ref())?;
                    Delta { claims: o.claims, pins: Some(o.pins) }
                }
                UpdateData::Delta(d) => de(d.as_ref())?,
                UpdateData::StateAndDelta { delta, .. } => de(delta.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            apply(&admin, &mut s, d).map_err(|_| ContractError::InvalidUpdate)?;
        }
        Ok(UpdateModification::valid(State::from(ser(&s)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(ser(&summarize(&de_or_default(state.as_ref())?))?))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(ser(&delta(&de_or_default(state.as_ref())?, &de_or_default(summary.as_ref())?))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sk(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn pk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    /// A valid claim, mining from `start` (about 2^18 hashes). Different starts give different strengths.
    fn claim(admin: &str, name: &str, k: &SigningKey, start: u64) -> Delta {
        let o = pk(k);
        let msg = claim_msg(admin, name, &o);
        let sig = hex::encode(k.sign(msg.as_bytes()).to_bytes());
        let nonce = (start..).find(|&n| zero_bits(&strength(admin, name, &o, &Claim { nonce: n, sig: String::new() })) >= POW_BITS).unwrap();
        Delta { claims: [(name.into(), [(o, Claim { nonce, sig })].into())].into(), pins: None }
    }

    fn pins(admin: &SigningKey, ts: u64, map: &[(&str, &str)]) -> Delta {
        let mut p = Pins { ts, map: map.iter().map(|(n, o)| (n.to_string(), o.to_string())).collect(), sig: String::new() };
        p.sig = hex::encode(admin.sign(pins_msg(&p).as_bytes()).to_bytes());
        Delta { claims: Default::default(), pins: Some(p) }
    }

    #[test]
    fn strength_vector_shared_with_ui() {
        let (a, o) = ("aa".repeat(32), "bb".repeat(32)); // same vector as ui/src/names.test.ts
        let h = strength(&a, "x", &o, &Claim { nonce: 7, sig: String::new() });
        assert_eq!(hex::encode(h), "d62d6f096a13690dea0ee38885ab0645ff8b124129f1958a15075ecf78ff3125");
    }

    #[test]
    fn strongest_claim_wins_in_any_order() {
        let a = pk(&sk(1));
        let (c2, c3) = (claim(&a, "music", &sk(2), 0), claim(&a, "music", &sk(3), 0));
        let (mut s1, mut s2) = (RegState::default(), RegState::default());
        apply(&a, &mut s1, c2.clone()).unwrap();
        apply(&a, &mut s1, c3.clone()).unwrap();
        apply(&a, &mut s2, c3).unwrap();
        apply(&a, &mut s2, c2).unwrap();
        assert_eq!(s1, s2);
        validate(&a, &s1).unwrap();
        let m = &s1.claims["music"];
        let best = m.iter().min_by_key(|(o, c)| strength(&a, "music", o, c)).unwrap().0;
        assert_eq!(resolve(&a, &s1, "music"), Some(best.as_str()));
        // delta vs summary
        assert_eq!(delta(&s1, &Summary::default()).claims["music"].len(), 2);
        let d = delta(&s1, &summarize(&s1));
        assert!(d.claims.is_empty() && d.pins.is_none());
    }

    #[test]
    fn rejects_forged_and_lazy_claims() {
        let a = pk(&sk(1));
        let mut s = RegState::default();
        let good = claim(&a, "site", &sk(2), 0);
        // signed by someone else than the owner it names
        let mut forged = good.clone();
        let c = forged.claims.get_mut("site").unwrap().remove(&pk(&sk(2))).unwrap();
        forged.claims.get_mut("site").unwrap().insert(pk(&sk(3)), c);
        assert!(apply(&a, &mut s, forged).is_err());
        // bound to this registry: the same claim does not hold under another admin
        assert!(apply(&pk(&sk(9)), &mut RegState::default(), good.clone()).is_err());
        let mut lazy = good.clone();
        lazy.claims.get_mut("site").unwrap().values_mut().for_each(|c| c.nonce += 1); // fails the difficulty with p = 1 - 2^-18
        assert!(apply(&a, &mut s, lazy).is_err());
        assert!(apply(&a, &mut s, claim(&a, "Bad", &sk(2), 0)).is_err());
        apply(&a, &mut s, good).unwrap();
        validate(&a, &s).unwrap();
    }

    #[test]
    fn pins_decide_and_reserve() {
        let admin = sk(1);
        let a = pk(&admin);
        let mut s = RegState::default();
        apply(&a, &mut s, claim(&a, "music", &sk(2), 0)).unwrap();
        // pinned to an owner with no claim at all: the pin still wins
        apply(&a, &mut s, pins(&admin, 1, &[("music", &pk(&sk(4))), ("admin", "")])).unwrap();
        assert_eq!(resolve(&a, &s, "music"), Some(pk(&sk(4)).as_str()));
        assert_eq!(resolve(&a, &s, "admin"), None);
        // only the admin pins, and older pins never come back
        assert!(apply(&a, &mut s, pins(&sk(9), 2, &[])).is_err());
        apply(&a, &mut s, pins(&admin, 3, &[])).unwrap();
        apply(&a, &mut s, pins(&admin, 1, &[("music", "")])).unwrap();
        assert_eq!(resolve(&a, &s, "music"), Some(pk(&sk(2)).as_str()));
        validate(&a, &s).unwrap();
    }

    #[test]
    fn prune_keeps_strongest_per_name() {
        let a = pk(&sk(1));
        let mut s = RegState::default();
        for i in 2..=6 {
            apply(&a, &mut s, claim(&a, "x", &sk(i), 0)).unwrap();
        }
        assert_eq!(s.claims["x"].len(), PER_NAME);
        let mut kept: Vec<_> = s.claims["x"].iter().map(|(o, c)| strength(&a, "x", o, c)).collect();
        kept.sort();
        let worst_kept = kept[PER_NAME - 1];
        let all_strengths: Vec<_> = (2..=6).map(|i| claim(&a, "x", &sk(i), 0)).flat_map(|d| d.claims["x"].clone()).map(|(o, c)| strength(&a, "x", &o, &c)).collect();
        assert_eq!(all_strengths.iter().filter(|h| **h <= worst_kept).count(), PER_NAME);
        validate(&a, &s).unwrap();
    }
}
