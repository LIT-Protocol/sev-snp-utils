use bytes::Bytes;
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::pkey::Public;
use openssl::stack::{Stack};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use crate::common::binary::bin_vec_reverse_bytes;


pub fn x509_validate_signature(root_cert: X509, intermediate_cert: Option<X509>, child_cert: X509) -> Result<(), ErrorStack> {
    let mut store_builder = X509StoreBuilder::new()?;

    store_builder.add_cert(root_cert)?;

    if let Some(intermediate_cert) = intermediate_cert {
        store_builder.add_cert(intermediate_cert)?;
    }

    let store = store_builder.build();

    let chain = Stack::new().unwrap();

    let mut store_ctx = X509StoreContext::new()?;

    store_ctx.init(&store, &child_cert, &chain,
                   |c| c.verify_cert())?;

    Ok(())
}

pub fn x509_bytes_to_ec_key(bytes: Bytes) -> Result<EcKey<Public>, ErrorStack> {
    x509_to_ec_key(X509::from_der(bytes.as_ref())?)
}

pub fn x509_to_ec_key(cert: X509) -> Result<EcKey<Public>, ErrorStack> {
    cert.public_key()?.ec_key()
}

pub fn bignum_from_le_slice(vec: &Vec<u8>) -> Result<BigNum, ErrorStack> {
    BigNum::from_slice(bin_vec_reverse_bytes(vec).as_slice())
}

pub fn ecdsa_sig(r: &Vec<u8>, s: &Vec<u8>) -> Result<EcdsaSig, ErrorStack>  {
    EcdsaSig::from_private_components(
        bignum_from_le_slice(r)?,
        bignum_from_le_slice(s)?,
    )
}