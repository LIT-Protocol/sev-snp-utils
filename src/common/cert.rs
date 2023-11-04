use crate::common::binary::bin_vec_reverse_bytes;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::sign::any_ecdsa_type;
use rustls::sign::CertifiedKey;
use rustls::sign::Signer;
use rustls::Certificate;
use rustls::Error;
use rustls::RootCertStore;

pub fn x509_validate_signature(
    root_cert: Certificate,
    intermediate_cert: Option<Certificate>,
    child_cert: Certificate,
) -> Result<(), Error> {
    let mut root_store = RootCertStore::empty();

    root_store.add(&root_cert)?;

    if let Some(intermediate_cert) = intermediate_cert {
        root_store.add(&intermediate_cert)?;
    }

    root_store.verify_server_cert(&root_store, &vec![child_cert], &[])?;

    Ok(())
}

pub fn x509_to_ec_key(cert: Certificate) -> Result<CertifiedKey, Error> {
    let key = CertifiedKey::new(cert, any_ecdsa_type::ECDSA_SHA256_SIGNER)?;
    Ok(key)
}

pub fn bignum_from_le_slice(vec: &Vec<u8>) -> PayloadU16 {
    PayloadU16::new(bin_vec_reverse_bytes(vec))
}

pub fn ecdsa_sig(r: &Vec<u8>, s: &Vec<u8>) -> Result<DigitallySignedStruct, Error> {
    let mut sig = DigitallySignedStruct::new();
    sig.set_scheme(any_ecdsa_type::SIGNATURE_ECDSA_SHA256);
    sig.set_signature(bignum_from_le_slice(r));
    sig.set_signature(bignum_from_le_slice(s));
    Ok(sig)
}
