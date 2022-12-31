use std::path::Path;

use crate::error::Result;
pub use crate::guest::identity::types::{FamilyId, IdAuthInfo, IdBlock, ImageId, LaunchDigest};
use crate::guest::identity::types::ID_BLK_VERSION;

pub mod types;
pub mod ecdsa;

pub fn create_identity_block(ld: LaunchDigest,
                               family_id: FamilyId,
                               image_id: ImageId,
                               guest_svn: u32,
                               policy: u64,
                               id_key_pem_path: &Path,
                               author_key_pem_path: Option<&Path>) -> Result<(IdBlock, IdAuthInfo)> {
    let id_block = IdBlock::new(ld, family_id, image_id, ID_BLK_VERSION as u32,
                                guest_svn, policy);

    unimplemented!();

    //Ok((id_block))
}