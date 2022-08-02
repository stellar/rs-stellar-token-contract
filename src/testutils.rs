#![cfg(feature = "testutils")]

use crate::contract::Domain;
use crate::public_types::{
    Authorization, Identifier, KeyedAuthorization, KeyedEd25519Signature, Message, MessageV0,
};
use crate::*;
use ed25519_dalek::Keypair;
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{BigInt, Binary, Env, EnvVal, FixedBinary, IntoVal, Vec};

pub fn register_test_contract(e: &Env, contract_id: &[u8; 32]) {
    let contract_id = FixedBinary::from_array(e, *contract_id);
    e.register_contract(&contract_id, crate::contract::Token {});
}

pub fn to_ed25519(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().into_val(e))
}

pub struct Token {
    env: Env,
    contract_id: FixedBinary<32>,
}

impl Token {
    pub fn new(env: &Env, contract_id: &[u8; 32]) -> Self {
        Self {
            env: env.clone(),
            contract_id: FixedBinary::from_array(env, *contract_id),
        }
    }

    pub fn initialize(&self, admin: &Identifier, decimals: u32, name: &str, symbol: &str) {
        let name: Binary = name.into_val(&self.env);
        let symbol: Binary = symbol.into_val(&self.env);
        initialize(
            &self.env,
            &self.contract_id,
            admin,
            &decimals,
            &name,
            &symbol,
        )
    }

    pub fn nonce(&self, id: &Identifier) -> BigInt {
        nonce(&self.env, &self.contract_id, id)
    }

    pub fn allowance(&self, from: &Identifier, spender: &Identifier) -> BigInt {
        allowance(&self.env, &self.contract_id, from, spender)
    }

    pub fn approve(&self, from: &Keypair, spender: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(spender.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, from)),
            domain: Domain::Approve as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Signature {
            public_key: from.public.to_bytes().into_val(&self.env),
            signature: from.sign(msg).unwrap().into_val(&self.env),
        });
        approve(&self.env, &self.contract_id, &auth, spender, amount)
    }

    pub fn balance(&self, id: &Identifier) -> BigInt {
        balance(&self.env, &self.contract_id, id)
    }

    pub fn is_frozen(&self, id: &Identifier) -> bool {
        is_frozen(&self.env, &self.contract_id, id)
    }

    pub fn xfer(&self, from: &Keypair, to: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, from)),
            domain: Domain::Transfer as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Signature {
            public_key: FixedBinary::from_array(&self.env, from.public.to_bytes()),
            signature: from.sign(msg).unwrap().into_val(&self.env),
        });
        xfer(&self.env, &self.contract_id, &auth, to, amount)
    }

    pub fn xfer_from(
        &self,
        spender: &Keypair,
        from: &Identifier,
        to: &Identifier,
        amount: &BigInt,
    ) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(from.clone().into_env_val(&self.env));
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, spender)),
            domain: Domain::TransferFrom as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Signature {
            public_key: spender.public.to_bytes().into_val(&self.env),
            signature: spender.sign(msg).unwrap().into_val(&self.env),
        });
        xfer_from(&self.env, &self.contract_id, &auth, from, to, amount)
    }

    pub fn burn(&self, admin: &Keypair, from: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(from.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: Domain::Burn as u32,
            parameters: args,
        });
        let auth = Authorization::Ed25519(admin.sign(msg).unwrap().into_val(&self.env));
        burn(&self.env, &self.contract_id, &auth, from, amount)
    }

    pub fn freeze(&self, admin: &Keypair, id: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(id.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: Domain::Freeze as u32,
            parameters: args,
        });
        let auth = Authorization::Ed25519(admin.sign(msg).unwrap().into_val(&self.env));
        freeze(&self.env, &self.contract_id, &auth, id)
    }

    pub fn mint(&self, admin: &Keypair, to: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: Domain::Mint as u32,
            parameters: args,
        });
        let auth = Authorization::Ed25519(admin.sign(msg).unwrap().into_val(&self.env));
        mint(&self.env, &self.contract_id, &auth, to, amount)
    }

    pub fn set_admin(&self, admin: &Keypair, new_admin: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(new_admin.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: Domain::SetAdministrator as u32,
            parameters: args,
        });
        let auth = Authorization::Ed25519(admin.sign(msg).unwrap().into_val(&self.env));
        set_admin(&self.env, &self.contract_id, &auth, new_admin)
    }

    pub fn unfreeze(&self, admin: &Keypair, id: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(id.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: Domain::Unfreeze as u32,
            parameters: args,
        });
        let auth = Authorization::Ed25519(admin.sign(msg).unwrap().into_val(&self.env));
        unfreeze(&self.env, &self.contract_id, &auth, id)
    }

    pub fn decimals(&self) -> u32 {
        decimals(&self.env, &self.contract_id)
    }

    pub fn name(&self) -> Binary {
        name(&self.env, &self.contract_id)
    }

    pub fn symbol(&self) -> Binary {
        symbol(&self.env, &self.contract_id)
    }
}
