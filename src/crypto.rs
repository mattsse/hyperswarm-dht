use crate::rpc::fill_random_bytes;
use blake2::crypto_mac::generic_array::{typenum::U64, GenericArray};
use blake2::{Blake2b, Blake2s, VarBlake2b};
use ed25519_dalek::SignatureError;
pub use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature};

/// VALUE_MAX_SIZE + packet overhead (i.e. the key etc.)
/// should be less than the network MTU, normally 1400 bytes
pub const VALUE_MAX_SIZE: u64 = 1000;

const SALT_SEG: &str = "4:salt";
const SEQ_SEG: &str = "3:seqi";
const V_SEG: &str = "1:v";

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
fn hash(val: &[u8]) -> GenericArray<u8, U64> {
    use blake2::Digest;
    let mut hasher = Blake2b::new();
    hasher.update(val);
    hasher.finalize()
}

/// Generate a new `Ed25519` key pair.
#[inline]
pub fn keypair() -> Keypair {
    use rand::rngs::{OsRng, StdRng};
    use rand::SeedableRng;
    Keypair::generate(&mut StdRng::from_rng(OsRng::default()).unwrap())
}
