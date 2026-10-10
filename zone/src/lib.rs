//! Zone: the names one key publishes. Parameters = the owner's ed25519 pubkey (32 bytes), so anyone who
//! knows the key can find the zone. Each record maps a name to a contract instance id and is signed by
//! the owner; the newest record per name wins, and an empty target is a tombstone. `@` is the zone's
//! own root (what the bare name resolves to). State is JSON.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ROOT: &str = "@";
pub const MAX_RECORDS: usize = 1000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub target: String, // contract instance id (base58), empty = removed
    pub ts: u64,
    pub sig: String, // hex, by the owner over `fnz1|<owner>|<name>|<target>|<ts>`
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Zone {
    pub records: BTreeMap<String, Record>,
}

pub type Summary = BTreeMap<String, u64>;

pub type R<T> = Result<T, String>;

pub fn key(hexstr: &str) -> R<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hexstr)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes")?;
    VerifyingKey::from_bytes(&b).map_err(|e| e.to_string())
}

pub fn verify(k: &VerifyingKey, msg: &[u8], sig_hex: &str) -> R<()> {
    let sig = Signature::from_slice(&hex::decode(sig_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    k.verify(msg, &sig).map_err(|_| "bad signature".to_string())
}

/// A contract instance id (base58).
pub fn is_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Lowercase ASCII letters, digits and inner hyphens, 1 to 63 long: no look-alike characters.
pub fn valid_name(n: &str) -> bool {
    (1..=63).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !n.starts_with('-')
        && !n.ends_with('-')
}

fn check_record(owner: &str, name: &str, r: &Record) -> R<()> {
    if name != ROOT && !valid_name(name) {
        return Err("bad name".into());
    }
    if !r.target.is_empty() && !is_id(&r.target) {
        return Err("bad target".into());
    }
    verify(&key(owner)?, format!("fnz1|{owner}|{name}|{}|{}", r.target, r.ts).as_bytes(), &r.sig)
}

/// Does `new` replace `old`? Newer wins; equal times fall back to the signature so every merge order agrees.
fn newer(new: &Record, old: &Record) -> bool {
    (new.ts, &new.sig) > (old.ts, &old.sig)
}

pub fn validate(owner: &str, z: &Zone) -> R<()> {
    if z.records.len() > MAX_RECORDS {
        return Err("too many records".into());
    }
    z.records.iter().try_for_each(|(n, r)| check_record(owner, n, r))
}

pub fn apply(owner: &str, z: &mut Zone, d: Zone) -> R<()> {
    for (name, r) in d.records {
        if z.records.get(&name).is_some_and(|old| !newer(&r, old)) {
            continue;
        }
        check_record(owner, &name, &r)?;
        z.records.insert(name, r);
    }
    if z.records.len() > MAX_RECORDS {
        return Err("too many records".into());
    }
    Ok(())
}

pub fn summarize(z: &Zone) -> Summary {
    z.records.iter().map(|(n, r)| (n.clone(), r.ts)).collect()
}

pub fn delta(z: &Zone, sum: &Summary) -> Zone {
    Zone {
        records: z
            .records
            .iter()
            .filter(|(n, r)| sum.get(*n).is_none_or(|&t| t <= r.ts)) // equal ts may still differ: let the receiver decide
            .map(|(n, r)| (n.clone(), r.clone()))
            .collect(),
    }
}

/// Where `name` points, if anywhere.
pub fn resolve<'a>(z: &'a Zone, name: &str) -> Option<&'a str> {
    z.records.get(name).map(|r| r.target.as_str()).filter(|t| !t.is_empty())
}

// ---- Freenet glue ----

fn owner(p: &Parameters) -> String {
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
        let z: Zone = de_or_default(state.as_ref())?;
        Ok(match validate(&owner(&parameters), &z) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let owner = owner(&parameters);
        let mut z: Zone = de_or_default(state.as_ref())?;
        for u in data {
            let d: Zone = match u {
                UpdateData::State(st) => de(st.as_ref())?,
                UpdateData::Delta(d) => de(d.as_ref())?,
                UpdateData::StateAndDelta { delta, .. } => de(delta.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            apply(&owner, &mut z, d).map_err(|_| ContractError::InvalidUpdate)?;
        }
        Ok(UpdateModification::valid(State::from(ser(&z)?)))
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
    fn rec(k: &SigningKey, name: &str, target: &str, ts: u64) -> Zone {
        let sig = hex::encode(k.sign(format!("fnz1|{}|{name}|{target}|{ts}", pk(k)).as_bytes()).to_bytes());
        Zone { records: [(name.into(), Record { target: target.into(), ts, sig })].into() }
    }

    #[test]
    fn owner_sets_and_removes_records() {
        let k = sk(1);
        let o = pk(&k);
        let mut z = Zone::default();
        validate(&o, &z).unwrap();
        apply(&o, &mut z, rec(&k, ROOT, "SiteA", 10)).unwrap();
        apply(&o, &mut z, rec(&k, "music", "MusicA", 10)).unwrap();
        assert_eq!(resolve(&z, ROOT), Some("SiteA"));
        // newer wins, older is ignored
        apply(&o, &mut z, rec(&k, "music", "MusicB", 20)).unwrap();
        apply(&o, &mut z, rec(&k, "music", "MusicA", 10)).unwrap();
        assert_eq!(resolve(&z, "music"), Some("MusicB"));
        // tombstone
        apply(&o, &mut z, rec(&k, "music", "", 30)).unwrap();
        assert_eq!(resolve(&z, "music"), None);
        validate(&o, &z).unwrap();
        // delta vs summary
        assert!(delta(&z, &Summary::default()).records.len() == 2);
        assert!(delta(&z, &[("music".to_string(), 31)].into()).records.keys().eq([ROOT]));
    }

    #[test]
    fn rejects_strangers_and_bad_input() {
        let o = pk(&sk(1));
        let mut z = Zone::default();
        assert!(apply(&o, &mut z, rec(&sk(2), "x", "T", 1)).is_err()); // not the owner
        assert!(apply(&o, &mut z, rec(&sk(1), "Bad", "T", 1)).is_err()); // uppercase
        assert!(apply(&o, &mut z, rec(&sk(1), "-x", "T", 1)).is_err());
        assert!(apply(&o, &mut z, rec(&sk(1), "x", "not an id!", 1)).is_err());
        let mut forged = rec(&sk(1), "x", "T", 1);
        forged.records.get_mut("x").unwrap().target = "Other".into();
        assert!(apply(&o, &mut z, forged).is_err());
        assert!(z.records.is_empty());
    }

    #[test]
    fn merge_order_does_not_matter() {
        let k = sk(1);
        let o = pk(&k);
        let (a, b) = (rec(&k, "x", "A", 5), rec(&k, "x", "B", 5)); // same time, different target
        let (mut z1, mut z2) = (Zone::default(), Zone::default());
        apply(&o, &mut z1, a.clone()).unwrap();
        apply(&o, &mut z1, b.clone()).unwrap();
        apply(&o, &mut z2, b).unwrap();
        apply(&o, &mut z2, a).unwrap();
        assert_eq!(z1, z2);
    }

    #[test]
    fn names() {
        for ok in ["a", "freetunes", "my-site-2", &"a".repeat(63)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "A", "-a", "a-", "a.b", "a/b", "à", &"a".repeat(64)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
