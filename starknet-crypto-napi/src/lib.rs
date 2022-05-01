mod error;

use error::Error;
use napi::bindgen_prelude::{Env, Object};
use napi_derive::napi;
use starknet_crypto::{pedersen_hash, rfc6979_generate_k, sign, verify, FieldElement, SignError};

struct Signature {
    r: String,
    s: String,
}

fn verify_stark_err(
    public_key: String,
    message_hash: String,
    signature_r: String,
    signature_s: String,
) -> Result<bool, Error> {
    let p_key = FieldElement::from_hex_be(&public_key)?;
    let m_hash = FieldElement::from_hex_be(&message_hash)?;
    let s_r = FieldElement::from_hex_be(&signature_r)?;
    let s_s = FieldElement::from_hex_be(&signature_s)?;
    let res = verify(&p_key, &m_hash, &s_r, &s_s)?;
    Ok(res)
}

#[napi]
pub fn verify_stark(
    public_key: String,
    message_hash: String,
    signature_r: String,
    signature_s: String,
) -> napi::Result<bool> {
    let res = verify_stark_err(public_key, message_hash, signature_r, signature_s)?;
    Ok(res)
}

fn sign_stark_err(private_key: String, message_hash: String) -> Result<Signature, Error> {
    let p_key = FieldElement::from_hex_be(&private_key)?;
    let m_hash = FieldElement::from_hex_be(&message_hash)?;

    let mut seed = None;

    loop {
        let k = rfc6979_generate_k(&m_hash, &p_key, seed.as_ref());

        match sign(&p_key, &m_hash, &k) {
            Ok(sig) => {
                return Ok(Signature {
                    r: format!("{:#x}", sig.r),
                    s: format!("{:#x}", sig.s),
                });
            }
            Err(SignError::InvalidK) => {
                seed = match seed {
                    Some(prev_seed) => Some(prev_seed + FieldElement::ONE),
                    None => Some(FieldElement::ONE),
                };
            }
            Err(e) => {
                return Err(Error::from(e));
            }
        };
    }
}

#[napi]
pub fn sign_stark(env: Env, private_key: String, message_hash: String) -> napi::Result<Object> {
    let sig = sign_stark_err(private_key, message_hash)?;
    let mut obj = env.create_object()?;
    obj.set("r", sig.r)?;
    obj.set("s", sig.s)?;
    Ok(obj)
}

fn pedersen_stark_err(x: String, y: String) -> Result<String, Error> {
    let x_ = FieldElement::from_hex_be(&x)?;
    let y_ = FieldElement::from_hex_be(&y)?;
    Ok(format!("{:x}", pedersen_hash(&x_, &y_)))
}

#[napi]
pub fn pedersen_stark(x: String, y: String) -> napi::Result<String> {
    let res = pedersen_stark_err(x, y)?;
    Ok(res)
}
