use crate::nonce::read_and_increment_nonce;
use crate::public_types::{
    KeyedAccountAuthorization, KeyedAuthorization, KeyedEd25519Signature, Message, MessageV0, U256,
};
use soroban_sdk::serde::Serialize;
use soroban_sdk::{Account, Env, EnvVal, IntoVal, RawVal};

pub trait ContractDataKey: Clone {}

fn check_ed25519_auth<T>(
    e: &Env,
    auth: &KeyedEd25519Signature,
    domain: u32,
    parameters: EnvVal,
    nonce_key: T,
) where
    T: IntoVal<Env, RawVal> + ContractDataKey,
{
    let msg = MessageV0 {
        nonce: read_and_increment_nonce(&e, nonce_key),
        domain: domain,
        parameters: parameters.try_into().unwrap(),
    };
    let msg_bin = Message::V0(msg).serialize(e);

    e.verify_sig_ed25519(
        auth.public_key.clone().into(),
        msg_bin,
        auth.signature.clone().into(),
    );
}

fn check_account_auth<T>(
    e: &Env,
    auth: &KeyedAccountAuthorization,
    domain: u32,
    parameters: EnvVal,
    nonce_key: T,
) where
    T: IntoVal<Env, RawVal> + ContractDataKey,
{
    let acc = Account::from_public_key(&auth.public_key).unwrap();

    let msg = MessageV0 {
        nonce: read_and_increment_nonce(&e, nonce_key),
        domain: domain,
        parameters: parameters.try_into().unwrap(),
    };
    let msg_bin = Message::V0(msg).serialize(e);

    let threshold = acc.medium_threshold();
    let mut weight = 0u32;

    let sigs = &auth.signatures;
    let mut prev_pk: Option<U256> = None;
    for sig in sigs.iter().map(Result::unwrap) {
        // Cannot take multiple signatures from the same key
        if let Some(prev) = prev_pk {
            if prev >= sig.public_key {
                panic!("signature out of order")
            }
        }

        e.verify_sig_ed25519(
            sig.public_key.clone().into(),
            msg_bin.clone(),
            sig.signature.into(),
        );
        // TODO: Check for overflow
        weight += acc.signer_weight(&sig.public_key);

        prev_pk = Some(sig.public_key);
    }

    if weight < threshold {
        panic!("insufficient signing weight")
    }
}

pub fn check_auth<T>(
    e: &Env,
    auth: &KeyedAuthorization,
    domain: u32,
    parameters: EnvVal,
    nonce_key: Option<T>,
) where
    T: IntoVal<Env, RawVal> + ContractDataKey,
{
    match auth {
        KeyedAuthorization::Contract => {
            if nonce_key.is_some() {
                panic!("nonce_key should not be specified for contract");
            }
            e.get_invoking_contract();
        }
        KeyedAuthorization::Ed25519(kea) => check_ed25519_auth(
            e,
            kea,
            domain,
            parameters,
            nonce_key.expect("nonce is missing"),
        ),
        KeyedAuthorization::Account(kaa) => check_account_auth(
            e,
            kaa,
            domain,
            parameters,
            nonce_key.expect("nonce is missing"),
        ),
    }
}
