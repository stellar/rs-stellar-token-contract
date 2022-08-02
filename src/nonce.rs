use soroban_sdk::{BigInt, Env, IntoVal, RawVal};

use crate::cryptography::ContractDataKey;

pub fn read_nonce<T>(e: &Env, nonce_key: T) -> BigInt
where
    T: IntoVal<Env, RawVal>,
{
    if let Some(nonce) = e.contract_data().get(nonce_key) {
        nonce.unwrap()
    } else {
        BigInt::zero(e)
    }
}

pub fn read_and_increment_nonce<T>(e: &Env, nonce_key: T) -> BigInt
where
    T: IntoVal<Env, RawVal> + ContractDataKey,
{
    let nonce = read_nonce(e, nonce_key.clone());
    e.contract_data()
        .set(nonce_key, nonce.clone() + BigInt::from_u32(e, 1));
    nonce
}
