use std::path::Path;

use crate::error::Result;
use crate::guest::identity::ecdsa::create_signed_id_auth_info;
pub use crate::guest::identity::types::{BlockSigner, FamilyId, IdAuthInfo, IdBlock, ImageId,
                                        LaunchDigest, ToBase64};
pub use crate::guest::identity::fingerprint::{fingerprint_id_key, fingerprint_id_key_as_hex};

pub mod types;
pub mod ecdsa;
pub mod fingerprint;

pub fn create_identity_block(ld: LaunchDigest,
                             family_id: FamilyId,
                             image_id: ImageId,
                             guest_svn: u32,
                             policy: u64,
                             id_key_pem_path: &Path,
                             author_key_pem_path: Option<&Path>) -> Result<(IdBlock, IdAuthInfo)> {
    let id_block = IdBlock::new(ld, family_id, image_id, guest_svn, policy);

    let id_auth_info = create_signed_id_auth_info(&id_block, id_key_pem_path,
                                                  author_key_pem_path)?;

    Ok((id_block, id_auth_info))
}