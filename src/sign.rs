/// VALUE_MAX_SIZE + packet overhead (i.e. the key etc.)
/// should be less than the network MTU, normally 1400 bytes
const VALUE_MAX_SIZE: u64 = 1000;

const SALT_SEG: &str = "4:salt";
const SEQ_SEG: &str = "3:seqi";
const V_SEG: &str = "1:v";

#[inline]
pub fn salt() {
    unimplemented!()
}

#[inline]
pub fn sign() {
    unimplemented!()
}
