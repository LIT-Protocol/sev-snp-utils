use std::fs;
use std::path::Path;
use openssl::ec::EcKey;
use crate::guest::identity::{IdAuthInfo, IdBlock};
use crate::error::{conversion, map_io_err, Result};

pub(crate) fn create_signed_id_auth_info(id_block: &IdBlock,
                                         id_key_pem_path: &Path,
                                         author_key_pem_path: Option<&Path>) -> Result<IdAuthInfo> {
    // TESTING: Refactor
    let id_key_pem_bytes = fs::read(id_key_pem_path)
        .map_err(map_io_err)?;
    let id_key = EcKey::private_key_from_pem(&id_key_pem_bytes[..])
        .map_err(|e| conversion(e, None))?;

    let pub_key = id_key.public_key();


    // TESTING

    unimplemented!();
}