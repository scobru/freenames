//! whoiam delegation. A whoiam persona authorizes an app key with one "sign in with whoiam" proof: the
//! app asks whoiam to sign the challenge `wd1.<app key hex>.<nonce>`, and the proof (a certificate) then
//! says "this app key acts for me in the app served at this path". Contracts check the certificate, then
//! the app key's signature on each write, so the persona is the identity and the app key is disposable.
//! whoiam signs "whoiam-connect-v1" || pk || u32le len || return_base || u32le len || challenge || u64le ts
//! (skandragon/freenet-whoiam, common/src/connect.rs).
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "wd1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Cert {
    pub base: String,      // the app's return URL (origin + path) whoiam signed for
    pub challenge: String, // `wd1.<app key hex>.<nonce>`
    pub ts: u64,
    pub sig: String, // hex, by the persona
}

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

pub fn connect_message(pk: &[u8; 32], base: &str, challenge: &str, ts: u64) -> Vec<u8> {
    let mut m = b"whoiam-connect-v1".to_vec();
    m.extend_from_slice(pk);
    for f in [base, challenge] {
        m.extend_from_slice(&(f.len() as u32).to_le_bytes());
        m.extend_from_slice(f.as_bytes());
    }
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

/// `http://host:port/path` -> `/path`: the same app has a different host on every node.
fn path_of(base: &str) -> Option<&str> {
    let rest = base.strip_prefix("http://").or_else(|| base.strip_prefix("https://"))?;
    Some(&rest[rest.find('/')?..])
}

/// Check that `c` is `persona`'s delegation to an app key, for the app served at `app_path`. Returns that key.
pub fn check(persona: &str, app_path: &str, c: &Cert) -> R<VerifyingKey> {
    if path_of(&c.base) != Some(app_path) {
        return Err("certificate is for another app".into());
    }
    let parts: Vec<&str> = c.challenge.split('.').collect();
    let [PREFIX, app_key, nonce] = parts[..] else {
        return Err("not a delegation".into());
    };
    if nonce.is_empty() {
        return Err("not a delegation".into());
    }
    let p = key(persona)?;
    verify(&p, &connect_message(p.as_bytes(), &c.base, &c.challenge, c.ts), &c.sig)?;
    key(app_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn matches_whoiam_golden_vector() {
        let sk = SigningKey::from_bytes(&[42; 32]);
        let m = connect_message(sk.verifying_key().as_bytes(), "https://example.com/app", "abc123", 12345);
        // from whoiam: common/src/connect.rs, golden_connect_signature
        assert_eq!(
            hex::encode(sk.sign(&m).to_bytes()),
            "122b675bdbc8772f52631524ac2b500dec76721bff7c0b299025df04e18e8e8ddf2b8d0a232a5785e68d5738be4f5111ae7b58106f5458b966b9b365fff5ac09"
        );
    }

    fn cert(persona: &SigningKey, base: &str, challenge: &str) -> Cert {
        let sig = persona.sign(&connect_message(persona.verifying_key().as_bytes(), base, challenge, 7));
        Cert { base: base.into(), challenge: challenge.into(), ts: 7, sig: hex::encode(sig.to_bytes()) }
    }

    #[test]
    fn delegation_is_bound_to_persona_app_and_key() {
        let (p, app) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let ph = hex::encode(p.verifying_key().as_bytes());
        let ak = hex::encode(app.verifying_key().as_bytes());
        let base = "http://127.0.0.1:7509/v1/contract/web/App1/";
        let c = cert(&p, base, &format!("wd1.{ak}.n1"));
        assert_eq!(check(&ph, "/v1/contract/web/App1/", &c).unwrap(), app.verifying_key());
        // the same app on another node (other host) is accepted, another app is not
        let other_node = cert(&p, "http://10.0.0.5:7509/v1/contract/web/App1/", &format!("wd1.{ak}.n1"));
        assert!(check(&ph, "/v1/contract/web/App1/", &other_node).is_ok());
        assert!(check(&ph, "/v1/contract/web/App2/", &c).is_err());
        // another persona, a plain sign-in (not a delegation), a tampered key
        assert!(check(&hex::encode([9u8; 32]), "/v1/contract/web/App1/", &c).is_err());
        assert!(check(&ph, "/v1/contract/web/App1/", &cert(&p, base, "abc123")).is_err());
        let mut forged = c.clone();
        forged.challenge = format!("wd1.{}.n1", hex::encode(SigningKey::from_bytes(&[3; 32]).verifying_key().as_bytes()));
        assert!(check(&ph, "/v1/contract/web/App1/", &forged).is_err());
    }
}
