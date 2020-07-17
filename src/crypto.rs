use blake2::crypto_mac::generic_array::{typenum::U64, GenericArray};
use blake2::{Blake2b, VarBlake2b};
use ed25519_dalek::SignatureError;
pub use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature};

use crate::dht_proto::Mutable;
use crate::rpc::{fill_random_bytes, IdBytes};

/// VALUE_MAX_SIZE + packet overhead (i.e. the key etc.)
/// should be less than the network MTU, normally 1400 bytes
pub const VALUE_MAX_SIZE: u64 = 1000;

const SALT_SEG: &[u8; 6] = b"4:salt";

const SEQ_SEG: &[u8; 6] = b"3:seqi";

const V_SEG: &[u8; 3] = b"1:v";

/// Utility method for creating a random or hashed salt value.
///
/// # Panics
///
/// Size must be in range [16-64], panics otherwise
#[inline]
pub fn salt(val: &[u8], size: usize) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    assert!(size >= 16 && size <= 64);
    let mut salt = Vec::with_capacity(size);
    let mut hasher = VarBlake2b::new(size).unwrap();
    hasher.update(val);
    hasher.finalize_variable(|res| salt.extend_from_slice(res));
    salt
}

/// Fill a new `Vec` with `size` random bytes
///
/// # Panics
///
/// Size must be in range [16-64], panics otherwise
#[inline]
pub fn random_salt(size: usize) -> Vec<u8> {
    assert!(size >= 16 && size <= 64);
    let mut salt = vec![0; size];
    fill_random_bytes(&mut salt);
    salt
}

/// Sign a byte slice using a keypair's private key.
#[inline]
pub fn sign(public_key: &PublicKey, secret: &SecretKey, msg: &[u8]) -> Signature {
    ExpandedSecretKey::from(secret).sign(msg, public_key)
}

/// Verify a signature on a message with a keypair's public key.
#[inline]
pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
    public.verify(msg, sig)
}

/// Create a 64B `blake2b` hash of `val`.
#[inline]
pub fn hash(val: &[u8]) -> GenericArray<u8, U64> {
    use blake2::Digest;
    let mut hasher = Blake2b::new();
    hasher.update(val);
    hasher.finalize()
}

/// hash the `val` with a key size of U32 and put it into [`IdBytes`]
pub fn hash_id(val: &[u8]) -> IdBytes {
    use blake2::digest::{Update, VariableOutput};
    let mut key = [0; 32];
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.update(val);
    hasher.finalize_variable(|res| key.copy_from_slice(res));
    key.into()
}

/// Generate a new `Ed25519` key pair.
#[inline]
pub fn keypair() -> Keypair {
    use rand::rngs::{OsRng, StdRng};
    use rand::SeedableRng;
    Keypair::generate(&mut StdRng::from_rng(OsRng::default()).unwrap())
}

#[inline]
pub fn signable(mutable: &Mutable) -> Result<Vec<u8>, ()> {
    if let Some(ref val) = mutable.value {
        let cap = SEQ_SEG.len() + 3 + V_SEG.len() + 3 + val.len();

        let mut s = if let Some(ref salt) = mutable.salt {
            if salt.len() > 64 {
                return Err(());
            }
            let mut s = Vec::with_capacity(cap + SALT_SEG.len() + 3 + salt.len());
            s.extend_from_slice(SALT_SEG.as_ref());

            s.extend_from_slice(format!("{}:", salt.len()).as_bytes());

            s.extend_from_slice(salt.as_slice());
            s
        } else {
            Vec::with_capacity(cap)
        };

        s.extend_from_slice(SEQ_SEG.as_ref());

        s.extend_from_slice(format!("{}e", mutable.seq.unwrap_or_default()).as_bytes());

        s.extend_from_slice(V_SEG.as_ref());

        s.extend_from_slice(format!("{}:", val.len()).as_bytes());

        s.extend_from_slice(val.as_slice());

        Ok(s)
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signable_test() {
        let mutable = Mutable {
            value: Some(b"value".to_vec()),
            signature: None,
            seq: None,
            salt: None,
        };
        let sign = signable(&mutable).unwrap();

        assert_eq!(
            sign.as_slice(),
            &[51, 58, 115, 101, 113, 105, 48, 101, 49, 58, 118, 53, 58, 118, 97, 108, 117, 101][..]
        );

        assert_eq!(
            String::from_utf8(sign).unwrap().as_str(),
            "3:seqi0e1:v5:value"
        )
    }
}
