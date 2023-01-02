use std::fs;
use std::path::Path;

use bytemuck::{bytes_of, Zeroable};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::md::Md;
use openssl::md_ctx::MdCtx;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};

use crate::common::binary::{bin_vec_reverse_bytes};
use crate::error::{conversion, io, openssl, Result, validation};
use crate::guest::identity::{IdAuthInfo, IdBlock};
use crate::guest::identity::types::{ECDSA_POINT_SIZE, EcdsaCurve, SevAlgo, SevEcdsaPubKey, SevEcdsaPubKeyBody, SevEcdsaPubKeyInner, SevEcdsaSig, SevEcdsaSigBody, BlockSigner};

pub(crate) fn create_signed_id_auth_info(id_block: &IdBlock,
                                         id_key_pem_path: &Path,
                                         author_key_pem_path: Option<&Path>) -> Result<IdAuthInfo> {
    let mut id_auth_info = IdAuthInfo::zeroed();

    let (id_key, ec_id_key) = read_and_validate_id_key(id_key_pem_path)?;
    let id_pubkey = SevEcdsaPubKey::try_from(&ec_id_key)?;

    id_auth_info.id_key_algo = SevAlgo::SevAlgoEcdsaP384Sha384 as u32;
    id_auth_info.id_pubkey = id_pubkey;
    id_auth_info.id_block_sig = SevEcdsaSig::try_from((&id_key,
                                                       bytes_of(id_block)))?;

    if let Some(author_key_pem_path) = author_key_pem_path {
        let (author_key, ec_author_key) = read_and_validate_id_key(author_key_pem_path)?;
        let author_pubkey = SevEcdsaPubKey::try_from(&ec_author_key)?;

        id_auth_info.author_key_algo = SevAlgo::SevAlgoEcdsaP384Sha384 as u32;
        id_auth_info.author_pubkey = author_pubkey;
        id_auth_info.id_key_sig = SevEcdsaSig::try_from((&author_key,
                                                         bytes_of(&id_auth_info.id_pubkey)))?;
    }

    Ok(id_auth_info)
}

impl BlockSigner for IdBlock {
    fn sign(&self,
            id_key_pem_path: &Path,
            author_key_pem_path: Option<&Path>) -> Result<IdAuthInfo> {
        create_signed_id_auth_info(self, id_key_pem_path, author_key_pem_path)
    }
}

pub(crate) fn read_and_validate_id_key(path: &Path) -> Result<(PKey<Private>, EcKey<Private>)> {
    let key_pem_bytes = fs::read(path)
        .map_err(|e| io(e, Some(format!("failed to open: {:?}", path))))?;
    let key = PKey::private_key_from_pem(&key_pem_bytes[..])
        .map_err(|e| conversion(e, None))?;

    if key.id() != Id::EC {
        return Err(validation(format!("key must be of type 'EC' (path: {:?})", path), None));
    }

    let ec_key = key.ec_key()
        .map_err(|e| conversion(e, None))?;

    ec_key.check_key()
        .map_err(|e| validation(e, None))?;

    if let Some(name) = ec_key.group().curve_name() {
        if name != Nid::SECP384R1 {
            return Err(validation(format!("sev key must use curve 'secp384r1' (path: {:?})", path), None));
        }
    } else {
        return Err(validation(format!("sev key is invalid, missing curve data (path: {:?})", path), None));
    }

    Ok((key, ec_key))
}

impl TryFrom<&EcKey<Private>> for SevEcdsaPubKey {
    type Error = crate::error::Error;

    fn try_from(value: &EcKey<Private>) -> Result<Self> {
        let pub_key = value.public_key();

        let mut res = SevEcdsaPubKey::zeroed();
        res.curve = EcdsaCurve::EcdsaCurveP384 as u32;

        let mut ctx = BigNumContext::new().unwrap();
        let curve_group = EcGroup::from_curve_name(Nid::SECP384R1)
            .map_err(|e| conversion(e, None))?;

        let mut x = BigNum::new()
            .map_err(|e| conversion(e, None))?;
        let mut y = BigNum::new()
            .map_err(|e| conversion(e, None))?;

        pub_key.affine_coordinates(&curve_group, &mut x, &mut y,  &mut ctx)
            .map_err(|e| conversion(e, None))?;

        let padded_x = bin_vec_reverse_bytes(
            &x.to_vec_padded(ECDSA_POINT_SIZE as i32)
            .map_err(|e| conversion(e, None))?);
        let padded_y = bin_vec_reverse_bytes(
            &y.to_vec_padded(ECDSA_POINT_SIZE as i32)
            .map_err(|e| conversion(e, None))?);

        let mut inner = SevEcdsaPubKeyInner::zeroed();
        let mut body = SevEcdsaPubKeyBody::zeroed();

        body.qx = padded_x.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaPubKeyBody.qx", None))?;
        body.qy = padded_y.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaPubKeyBody.qy", None))?;

        inner.body = body;

        let mut bytes: Vec<u8> = Vec::from(body.qx);
        bytes.extend_from_slice(&body.qy);

        inner.bytes = bytes.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaPubKeyInner.bytes", None))?;

        res.inner = inner;

        Ok(res)
    }
}

impl TryFrom<(&PKey<Private>, &[u8])> for SevEcdsaSig {
    type Error = crate::error::Error;

    fn try_from((priv_key, data): (&PKey<Private>, &[u8])) -> Result<Self> {
        let mut ctx = MdCtx::new().unwrap();
        ctx.digest_sign_init(Some(Md::sha384()), priv_key).unwrap();

        ctx.digest_sign_update(data).unwrap();
        let mut signature = vec![];
        ctx.digest_sign_final_to_vec(&mut signature).unwrap();

        let sig = EcdsaSig::from_der(&signature[..])
            .map_err(|e| openssl(e, None))?;

        let padded_r = bin_vec_reverse_bytes(
            &sig.r().to_vec_padded(ECDSA_POINT_SIZE as i32)
                .map_err(|e| conversion(e, None))?);
        let padded_s = bin_vec_reverse_bytes(
            &sig.s().to_vec_padded(ECDSA_POINT_SIZE as i32)
                .map_err(|e| conversion(e, None))?);

        let mut res = SevEcdsaSig::zeroed();
        let mut body = SevEcdsaSigBody::zeroed();

        body.r = padded_r.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaSigBody.r", None))?;
        body.s = padded_s.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaSigBody.r", None))?;

        let mut bytes: Vec<u8> = Vec::from(body.r);
        bytes.extend_from_slice(&body.s);

        res.body = body;
        res.bytes = bytes.try_into()
            .map_err(|_e| conversion("unexpected bytes left over setting SevEcdsaPubKeyInner.bytes", None))?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::common::binary::fmt_slice_vec_to_hex;
    use crate::guest::identity::ecdsa::create_signed_id_auth_info;
    use crate::guest::identity::IdBlock;
    use crate::guest::identity::types::ECDSA_POINT_SIZE;

    const RESOURCES_TEST_DIR: &str = "resources/test/identity";

    #[test]
    fn create_signed_id_auth_info_test() {
        let id_key_pem_path = get_test_path("id-key.pem");
        let author_key_pem_path = get_test_path("author-key.pem");

        let id_auth_info = create_signed_id_auth_info(&IdBlock::default(),
                                   id_key_pem_path.as_path(),
                                   Some(author_key_pem_path.as_path()))
            .expect("failed to call create_signed_id_auth_info");

        assert_eq!(id_auth_info.id_key_algo, 1);
        assert_eq!(id_auth_info.author_key_algo, 1);
        unsafe {
            assert_eq!(id_auth_info.id_block_sig.body.r.len(), ECDSA_POINT_SIZE);
            assert_ne!(&id_auth_info.id_block_sig.body.r, &[0; ECDSA_POINT_SIZE]);
            assert!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.r).ends_with("000000000000000000000000000000000000000000000000"));
            assert_eq!(id_auth_info.id_block_sig.body.s.len(), ECDSA_POINT_SIZE);
            assert_ne!(&id_auth_info.id_block_sig.body.s, &[0; ECDSA_POINT_SIZE]);
            assert!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.s).ends_with("000000000000000000000000000000000000000000000000"));

            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.bytes),
                       format!("{}{}", fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.r), fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.s)));

            assert_eq!(id_auth_info.id_pubkey.curve, 2);
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.bytes), "485215abb30f7a2f89794c0ae30345ea3846c5439d6ff89265ea862505be7bc2e4d642c2f94a6c1b813ffd66fb21ff640000000000000000000000000000000000000000000000001cbfe7e621c1a7ff0c8baadff28b26330e713ddd0e8f3921d5fa3ea63ee180f6c92a6367aad3e4c48482f1d961a61503000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.body.qx), "485215abb30f7a2f89794c0ae30345ea3846c5439d6ff89265ea862505be7bc2e4d642c2f94a6c1b813ffd66fb21ff64000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.body.qy), "1cbfe7e621c1a7ff0c8baadff28b26330e713ddd0e8f3921d5fa3ea63ee180f6c92a6367aad3e4c48482f1d961a61503000000000000000000000000000000000000000000000000");
        }
        unsafe {
            assert_eq!(id_auth_info.id_key_sig.body.r.len(), ECDSA_POINT_SIZE);
            assert_ne!(&id_auth_info.id_key_sig.body.r, &[0; ECDSA_POINT_SIZE]);
            assert!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.r).ends_with("000000000000000000000000000000000000000000000000"));
            assert_eq!(id_auth_info.id_key_sig.body.s.len(), ECDSA_POINT_SIZE);
            assert_ne!(&id_auth_info.id_key_sig.body.s, &[0; ECDSA_POINT_SIZE]);
            assert!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.s).ends_with("000000000000000000000000000000000000000000000000"));

            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.bytes),
                       format!("{}{}", fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.r), fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.s)));

            assert_eq!(id_auth_info.id_pubkey.curve, 2);
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.bytes), "3441ad9a5aa58abf5416d6ae05d6527feb1eb0ee8c86898f43c6be011239dd7f0c3ccec59c89e323b8f3fa1ef5a2ba0a0000000000000000000000000000000000000000000000003d7de26dd160f0431a2ccb1f7ac0f1c983dfdb46ca86d5b2dba1b0b54b7802ed4dd8fa68ca333ad7ab0d3c50294226a3000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.body.qx), "3441ad9a5aa58abf5416d6ae05d6527feb1eb0ee8c86898f43c6be011239dd7f0c3ccec59c89e323b8f3fa1ef5a2ba0a000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.body.qy), "3d7de26dd160f0431a2ccb1f7ac0f1c983dfdb46ca86d5b2dba1b0b54b7802ed4dd8fa68ca333ad7ab0d3c50294226a3000000000000000000000000000000000000000000000000");
        }
    }

    // Util
    fn get_test_path(path: &str) -> PathBuf {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(RESOURCES_TEST_DIR);
        test_path.push(path);
        test_path
    }
}