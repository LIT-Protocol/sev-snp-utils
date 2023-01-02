use std::path::Path;
use bytemuck::bytes_of;
use crate::common::binary::fmt_bin_vec_to_hex;
use crate::common::hash::sha384;
use crate::error::Result;
use crate::guest::identity::ecdsa::read_and_validate_id_key;
use crate::guest::identity::types::SevEcdsaPubKey;

pub fn fingerprint_id_key(pem_path: &Path) -> Result<Vec<u8>> {
    let (_, ec_id_key) = read_and_validate_id_key(pem_path)?;
    let id_pubkey = SevEcdsaPubKey::try_from(&ec_id_key)?;

    Ok(sha384(bytes_of(&id_pubkey)).to_vec())
}

pub fn fingerprint_id_key_as_hex(pem_path: &Path) -> Result<String> {
    Ok(fmt_bin_vec_to_hex(&fingerprint_id_key(pem_path)?))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::guest::identity::fingerprint::{fingerprint_id_key_as_hex};

    const RESOURCES_TEST_DIR: &str = "resources/test/identity";

    #[test]
    fn fingerprint_id_key_test() {
        let id_key_pem_path = get_test_path("id-key.pem");
        let author_key_pem_path = get_test_path("author-key.pem");

        let id_key_fingerprint = fingerprint_id_key_as_hex(id_key_pem_path.as_path())
            .expect("failed to fingerprint 'id-key.pem'");
        let author_key_fingerprint = fingerprint_id_key_as_hex(author_key_pem_path.as_path())
            .expect("failed to fingerprint 'author-key.pem'");

        assert_eq!(id_key_fingerprint, "64a7dce6dcc44a98f0db95301dec5d33def24ffd71df2911663dd8603e18a6831ac6fafd2b67d983b338305db818516c");
        assert_eq!(author_key_fingerprint, "bbb27d63ea847e0412b5b07ccdd673a46212545aceaf6b87521467ab66b982ead7901a9a190bdd1ffacf656c7ac1e9cc");
    }

    // Util
    fn get_test_path(path: &str) -> PathBuf {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(RESOURCES_TEST_DIR);
        test_path.push(path);
        test_path
    }
}