//! Zone: the names one whoiam persona publishes for one app. Parameters = the persona's ed25519 pubkey
//! (32 bytes) followed by the app's path (`/v1/contract/web/<app id>/`), so anyone who knows the persona
//! can find the zone. Each record maps a name to a contract instance id. It is signed by an app key the
//! persona delegated with whoiam (see `whoiam-delegation`), and carries that delegation, so the persona
//! is the owner and app keys are disposable. The newest record per name wins, and an empty target is a
//! tombstone. `@` is the zone's own root (what the bare name resolves to). State is JSON.
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use whoiam_delegation::{check, verify, Cert, R};

pub const ROOT: &str = "@";
pub const MAX_RECORDS: usize = 1000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub target: String, // contract instance id (base58), empty = removed
    pub ts: u64,
    pub sig: String, // hex, by the delegated app key over `fnz2|<persona>|<name>|<target>|<ts>`
    pub cert: Cert,  // the persona's delegation to that key
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Zone {
    pub records: BTreeMap<String, Record>,
}

pub type Summary = BTreeMap<String, u64>;

/// Who may write: the persona (hex), through keys it delegated for the app at `app`.
pub struct Owner {
    pub persona: String,
    pub app: String,
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

fn check_record(o: &Owner, name: &str, r: &Record) -> R<()> {
    if name != ROOT && !valid_name(name) {
        return Err("bad name".into());
    }
    if !r.target.is_empty() && !is_id(&r.target) {
        return Err("bad target".into());
    }
    let app_key = check(&o.persona, &o.app, &r.cert)?;
    verify(&app_key, format!("fnz2|{}|{name}|{}|{}", o.persona, r.target, r.ts).as_bytes(), &r.sig)
}

/// Does `new` replace `old`? Newer wins; equal times fall back to the signature so every merge order agrees.
fn newer(new: &Record, old: &Record) -> bool {
    (new.ts, &new.sig) > (old.ts, &old.sig)
}

pub fn validate(o: &Owner, z: &Zone) -> R<()> {
    if z.records.len() > MAX_RECORDS {
        return Err("too many records".into());
    }
    z.records.iter().try_for_each(|(n, r)| check_record(o, n, r))
}

pub fn apply(o: &Owner, z: &mut Zone, d: Zone) -> R<()> {
    for (name, r) in d.records {
        if z.records.get(&name).is_some_and(|old| !newer(&r, old)) {
            continue;
        }
        check_record(o, &name, &r)?;
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

fn owner(p: &Parameters) -> Result<Owner, ContractError> {
    let b = p.as_ref();
    let bad = || ContractError::Deser("parameters: persona key (32 bytes) then app path".into());
    let app = std::str::from_utf8(b.get(32..).ok_or_else(bad)?).map_err(|_| bad())?;
    Ok(Owner { persona: hex::encode(&b[..32]), app: app.into() })
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
        Ok(match validate(&owner(&parameters)?, &z) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let owner = owner(&parameters)?;
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
    use whoiam_delegation::connect_message;

    const APP: &str = "/v1/contract/web/App1/";

    fn sk(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn pk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }
    fn owner(p: &SigningKey) -> Owner {
        Owner { persona: pk(p), app: APP.into() }
    }
    /// `persona` delegates `app_key` for the app at `path`.
    fn cert(persona: &SigningKey, app_key: &SigningKey, path: &str) -> Cert {
        let (base, challenge) = (format!("http://127.0.0.1:7509{path}"), format!("wd1.{}.n1", pk(app_key)));
        let sig = persona.sign(&connect_message(persona.verifying_key().as_bytes(), &base, &challenge, 1));
        Cert { base, challenge, ts: 1, sig: hex::encode(sig.to_bytes()) }
    }
    /// A record by `persona`, written with its delegated app key `a`.
    fn rec(persona: &SigningKey, a: &SigningKey, name: &str, target: &str, ts: u64) -> Zone {
        let sig = hex::encode(a.sign(format!("fnz2|{}|{name}|{target}|{ts}", pk(persona)).as_bytes()).to_bytes());
        Zone { records: [(name.into(), Record { target: target.into(), ts, sig, cert: cert(persona, a, APP) })].into() }
    }

    #[test]
    fn owner_sets_and_removes_records() {
        let (p, a) = (sk(1), sk(10));
        let o = owner(&p);
        let mut z = Zone::default();
        validate(&o, &z).unwrap();
        apply(&o, &mut z, rec(&p, &a, ROOT, "SiteA", 10)).unwrap();
        apply(&o, &mut z, rec(&p, &sk(11), "music", "MusicA", 10)).unwrap(); // another device of the same persona
        assert_eq!(resolve(&z, ROOT), Some("SiteA"));
        // newer wins, older is ignored
        apply(&o, &mut z, rec(&p, &a, "music", "MusicB", 20)).unwrap();
        apply(&o, &mut z, rec(&p, &a, "music", "MusicA", 10)).unwrap();
        assert_eq!(resolve(&z, "music"), Some("MusicB"));
        // tombstone
        apply(&o, &mut z, rec(&p, &a, "music", "", 30)).unwrap();
        assert_eq!(resolve(&z, "music"), None);
        validate(&o, &z).unwrap();
        // delta vs summary
        assert!(delta(&z, &Summary::default()).records.len() == 2);
        assert!(delta(&z, &[("music".to_string(), 31)].into()).records.keys().eq([ROOT]));
    }

    #[test]
    fn rejects_strangers_and_bad_input() {
        let (p, a) = (sk(1), sk(10));
        let o = owner(&p);
        let mut z = Zone::default();
        assert!(apply(&o, &mut z, rec(&sk(2), &a, "x", "T", 1)).is_err()); // another persona
        assert!(apply(&o, &mut z, rec(&p, &a, "Bad", "T", 1)).is_err()); // uppercase
        assert!(apply(&o, &mut z, rec(&p, &a, "-x", "T", 1)).is_err());
        assert!(apply(&o, &mut z, rec(&p, &a, "x", "not an id!", 1)).is_err());
        let mut forged = rec(&p, &a, "x", "T", 1);
        forged.records.get_mut("x").unwrap().target = "Other".into();
        assert!(apply(&o, &mut z, forged).is_err());
        // signed by a key the persona did not delegate
        let mut stranger = rec(&p, &a, "x", "T", 1);
        let sig = sk(12).sign(format!("fnz2|{}|x|T|1", pk(&p)).as_bytes());
        stranger.records.get_mut("x").unwrap().sig = hex::encode(sig.to_bytes());
        assert!(apply(&o, &mut z, stranger).is_err());
        // delegated for another app
        let mut other_app = rec(&p, &a, "x", "T", 1);
        other_app.records.get_mut("x").unwrap().cert = cert(&p, &a, "/v1/contract/web/App2/");
        assert!(apply(&o, &mut z, other_app).is_err());
        assert!(z.records.is_empty());
    }

    #[test]
    fn merge_order_does_not_matter() {
        let (p, a) = (sk(1), sk(10));
        let o = owner(&p);
        let (x, y) = (rec(&p, &a, "x", "A", 5), rec(&p, &a, "x", "B", 5)); // same time, different target
        let (mut z1, mut z2) = (Zone::default(), Zone::default());
        apply(&o, &mut z1, x.clone()).unwrap();
        apply(&o, &mut z1, y.clone()).unwrap();
        apply(&o, &mut z2, y).unwrap();
        apply(&o, &mut z2, x).unwrap();
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
