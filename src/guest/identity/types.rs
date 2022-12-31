use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use bytemuck::{bytes_of, Pod, Zeroable};
use libc::{c_uchar, c_uint, c_ulonglong};
use once_cell::sync::Lazy;
use crate::common::binary::fmt_slice_vec_to_hex;

use crate::error::{conversion, io, map_io_err, Result, validation};

pub(crate) const ID_BLK_DIGEST_BITS: usize = 384;
pub(crate) const ID_BLK_DIGEST_BYTES: usize = ID_BLK_DIGEST_BITS / 8;

pub(crate) const ID_BLK_FAMILY_ID_BITS: usize = 128;
pub(crate) const ID_BLK_FAMILY_ID_BYTES: usize = ID_BLK_FAMILY_ID_BITS / 8;

pub(crate) const ID_BLK_IMAGE_ID_BITS: usize = 128;
pub(crate) const ID_BLK_IMAGE_ID_BYTES: usize = ID_BLK_IMAGE_ID_BITS / 8;

pub(crate) const ID_BLK_VERSION: usize = 1;

pub(crate) const ID_AUTH_INFO_RESERVED1_BYTES: usize = 0x03F - 0x008 + 1;
pub(crate) const ID_AUTH_INFO_RESERVED2_BYTES: usize = 0x67F - 0x644 + 1;
pub(crate) const ID_AUTH_INFO_RESERVED3_BYTES: usize = 0xFFF - 0xC84 + 1;

pub(crate) const ECDSA_POINT_SIZE_BITS: usize = 576;
pub(crate) const ECDSA_POINT_SIZE: usize = ECDSA_POINT_SIZE_BITS / 8;
pub(crate) const ECDSA_PUBKEY_RSVD_SIZE: usize = 0x403 - 0x94 + 1;
pub(crate) const ECDSA_SIG_RSVD_SIZE: usize = 0x1ff - 0x90 + 1;

pub trait BlockSigner {
    fn sign(&self,
            id_key_pem_path: &Path,
            author_key_pem_path: Option<&Path>) -> Result<IdAuthInfo>;
}

pub trait ToBase64 {
    fn to_base64(&self) -> Result<String>;
    fn save_base64(&self, path: &Path) -> Result<()>;
}

pub(crate) static LD_ZEROED: Lazy<LaunchDigest> = Lazy::new(||
    LaunchDigest::zeroed());

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaunchDigest(pub [c_uchar; ID_BLK_DIGEST_BYTES]);

impl LaunchDigest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec().into()
    }

    pub fn from_reader(mut rdr: impl Read) -> Result<Self> {
        let mut us = LaunchDigest::zeroed();
        rdr.read_exact(&mut us.0)
            .map_err(map_io_err)?;

        Ok(us)
    }

    pub fn hex(&self) -> String {
        fmt_slice_vec_to_hex(&self.0)
    }
}

impl TryFrom<&[u8]> for LaunchDigest {
    type Error = crate::error::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != ID_BLK_DIGEST_BYTES {
            return Err(validation(format!("value is not correct length for LaunchDigest ({} vs {})",
                                          value.len(), ID_BLK_DIGEST_BYTES), None));
        }

        let value: [u8; ID_BLK_DIGEST_BYTES] = value[..ID_BLK_DIGEST_BYTES]
            .try_into()
            .map_err(|e| conversion(e, None))?;

        Ok(Self(value))
    }
}

impl FromStr for LaunchDigest {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| conversion(e, None))?;

        Self::try_from(&bytes[..])
    }
}

unsafe impl Zeroable for LaunchDigest {}

unsafe impl Pod for LaunchDigest {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FamilyId(pub [c_uchar; ID_BLK_FAMILY_ID_BYTES]);

impl FamilyId {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec().into()
    }

    pub fn from_reader(mut rdr: impl Read) -> Result<Self> {
        let mut us = FamilyId::zeroed();
        rdr.read_exact(&mut us.0)
            .map_err(map_io_err)?;

        Ok(us)
    }

    pub fn hex(&self) -> String {
        fmt_slice_vec_to_hex(&self.0)
    }
}

impl TryFrom<&[u8]> for FamilyId {
    type Error = crate::error::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != ID_BLK_FAMILY_ID_BYTES {
            return Err(validation(format!("value is not correct length for FamilyId ({} vs {})",
                                          value.len(), ID_BLK_FAMILY_ID_BYTES), None));
        }

        let value: [u8; ID_BLK_FAMILY_ID_BYTES] = value[..ID_BLK_FAMILY_ID_BYTES]
            .try_into()
            .map_err(|e| conversion(e, None))?;

        Ok(Self(value))
    }
}

impl FromStr for FamilyId {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| conversion(e, None))?;

        Self::try_from(&bytes[..])
    }
}

unsafe impl Zeroable for FamilyId {}

unsafe impl Pod for FamilyId {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImageId(pub [c_uchar; ID_BLK_IMAGE_ID_BYTES]);

impl ImageId {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec().into()
    }

    pub fn from_reader(mut rdr: impl Read) -> Result<Self> {
        let mut us = ImageId::zeroed();
        rdr.read_exact(&mut us.0)
            .map_err(map_io_err)?;

        Ok(us)
    }

    pub fn hex(&self) -> String {
        fmt_slice_vec_to_hex(&self.0)
    }
}

impl TryFrom<&[u8]> for ImageId {
    type Error = crate::error::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != ID_BLK_IMAGE_ID_BYTES {
            return Err(validation(format!("value is not correct length for ImageId ({} vs {})",
                                          value.len(), ID_BLK_IMAGE_ID_BYTES), None));
        }

        let value: [u8; ID_BLK_IMAGE_ID_BYTES] = value[..ID_BLK_IMAGE_ID_BYTES]
            .try_into()
            .map_err(|e| conversion(e, None))?;

        Ok(Self(value))
    }
}

impl FromStr for ImageId {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| conversion(e, None))?;

        Self::try_from(&bytes[..])
    }
}

unsafe impl Zeroable for ImageId {}

unsafe impl Pod for ImageId {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdBlock {
    ld: LaunchDigest,
    family_id: FamilyId,
    image_id: ImageId,
    version: c_uint,
    guest_svn: c_uint,
    policy: c_ulonglong,
}

impl IdBlock {
    pub fn default() -> Self {
        let mut us = Self::zeroed();
        us.version = ID_BLK_VERSION as u32;
        us
    }

    pub fn new(ld: LaunchDigest,
               family_id: FamilyId,
               image_id: ImageId,
               guest_svn: u32,
               policy: u64) -> Self {
        Self {
            ld,
            family_id,
            image_id,
            version: ID_BLK_VERSION as u32,
            guest_svn,
            policy,
        }
    }

    pub fn with_ld(mut self, ld: LaunchDigest) -> Self {
        self.ld = ld;
        self
    }

    pub fn with_family_id(mut self, family_id: FamilyId) -> Self {
        self.family_id = family_id;
        self
    }

    pub fn with_image_id(mut self, image_id: ImageId) -> Self {
        self.image_id = image_id;
        self
    }

    pub fn with_guest_svn(mut self, guest_svn: u32) -> Self {
        self.guest_svn = guest_svn;
        self
    }

    pub fn with_policy(mut self, policy: u64) -> Self {
        self.policy = policy;
        self
    }
}

impl ToBase64 for IdBlock {
    fn to_base64(&self) -> Result<String> {
        Ok(base64::encode(bytes_of(self)))
    }

    fn save_base64(&self, path: &Path) -> Result<()> {
        fs::write(path, self.to_base64()?)
            .map_err(|e| io(e, None))
    }
}

unsafe impl Zeroable for IdBlock {}
unsafe impl Pod for IdBlock {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdAuthInfo {
    pub id_key_algo: c_uint,
    pub author_key_algo: c_uint,
    reserved1: [c_uchar; ID_AUTH_INFO_RESERVED1_BYTES],
    pub id_block_sig: SevEcdsaSig,
    pub id_pubkey: SevEcdsaPubKey,
    reserved2: [c_uchar; ID_AUTH_INFO_RESERVED2_BYTES],
    pub id_key_sig: SevEcdsaSig,
    pub author_pubkey: SevEcdsaPubKey,
    reserved3: [c_uchar; ID_AUTH_INFO_RESERVED3_BYTES],
}

impl ToBase64 for IdAuthInfo {
    fn to_base64(&self) -> Result<String> {
        Ok(base64::encode(bytes_of(self)))
    }

    fn save_base64(&self, path: &Path) -> Result<()> {
        fs::write(path, self.to_base64()?)
            .map_err(|e| io(e, None))
    }
}

unsafe impl Zeroable for IdAuthInfo {}
unsafe impl Pod for IdAuthInfo {}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum SevAlgo {
    SevAlgoInvalid = 0,
    SevAlgoEcdsaP384Sha384 = 1,
    SevAlgoLimit,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum EcdsaCurve {
    EcdsaCurveInvalid = 0,
    EcdsaCurveP384 = 2,
    EcdsaCurveLimit
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SevEcdsaSig {
    pub body: SevEcdsaSigBody,
    pub bytes: [c_uchar; 2 * ECDSA_POINT_SIZE],
}

unsafe impl Zeroable for SevEcdsaSig {}
unsafe impl Pod for SevEcdsaSig {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaSigBody {
    pub r: [c_uchar; ECDSA_POINT_SIZE],
    pub s: [c_uchar; ECDSA_POINT_SIZE],
    reserved: [c_uchar; ECDSA_SIG_RSVD_SIZE],
}

unsafe impl Zeroable for SevEcdsaSigBody {}
unsafe impl Pod for SevEcdsaSigBody {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaPubKey {
    pub curve: c_uint,
    pub inner: SevEcdsaPubKeyInner,
}

unsafe impl Zeroable for SevEcdsaPubKey {}
unsafe impl Pod for SevEcdsaPubKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SevEcdsaPubKeyInner {
    pub body: SevEcdsaPubKeyBody,
    pub bytes: [c_uchar; 2 * ECDSA_POINT_SIZE],
}

unsafe impl Zeroable for SevEcdsaPubKeyInner {}
unsafe impl Pod for SevEcdsaPubKeyInner {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaPubKeyBody {
    pub qx: [c_uchar; ECDSA_POINT_SIZE],
    pub qy: [c_uchar; ECDSA_POINT_SIZE],
    reserved: [c_uchar; ECDSA_PUBKEY_RSVD_SIZE],
}

unsafe impl Zeroable for SevEcdsaPubKeyBody {}
unsafe impl Pod for SevEcdsaPubKeyBody {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use bytemuck::checked::try_from_bytes;
    use crate::common::binary::fmt_slice_vec_to_hex;
    use crate::guest::identity::{IdAuthInfo, IdBlock};
    use crate::guest::identity::types::ToBase64;
    use crate::{FamilyId, ImageId, LaunchDigest};

    const RESOURCES_TEST_DIR: &str = "resources/test/identity";

    #[test]
    fn launch_digest_hex_test() {
        let ld = LaunchDigest::from_str("ffb0cb7f01a5d5b122430d66f211326ab5cf11a9a5d3189ec53adf9a60730bc63d9856fe9fe602abd662861d0ee36007")
            .expect("failed to convert LaunchDigest from hex");

        assert_eq!(ld.hex(), "ffb0cb7f01a5d5b122430d66f211326ab5cf11a9a5d3189ec53adf9a60730bc63d9856fe9fe602abd662861d0ee36007");
    }

    #[test]
    fn image_id_hex_test() {
        let image_id = ImageId::from_str("ffb0cb7f01a5d5b122430d66f211326a")
            .expect("failed to convert ImageId from hex");

        assert_eq!(image_id.hex(), "ffb0cb7f01a5d5b122430d66f211326a");
    }

    #[test]
    fn family_id_hex_test() {
        let family_id = FamilyId::from_str("ffb0cb7f01a5d5b122430d66f211326a")
            .expect("failed to convert FamilyId from hex");

        assert_eq!(family_id.hex(), "ffb0cb7f01a5d5b122430d66f211326a");
    }

    #[test]
    fn id_block_test() {
        let id_block_path = get_test_path("id_block.b64");
        let id_block_b64 = fs::read(id_block_path.as_path())
            .expect("failed to read: 'id_block.b64'");
        let id_block_bytes = base64::decode(&id_block_b64[..])
            .expect("failed to decode: 'id_block.b64' as base64");

        let id_block: &IdBlock = try_from_bytes(&id_block_bytes[..])
            .expect("failed to decode 'id_block.b64' as an IdBlock");

        assert_eq!(id_block.ld.hex(), "ffb0cb7f01a5d5b122430d66f211326ab5cf11a9a5d3189ec53adf9a60730bc63d9856fe9fe602abd662861d0ee36007");
        assert_eq!(id_block.image_id.hex(), "00000000000000000000000000000000");
        assert_eq!(id_block.family_id.hex(), "00000000000000000000000000000000");
        assert_eq!(id_block.version, 1);
        assert_eq!(id_block.guest_svn, 0);
        assert_eq!(id_block.policy, 0x30000);

        assert_eq!(id_block.to_base64().unwrap(), String::from_utf8(id_block_b64).unwrap());
    }

    #[test]
    fn id_auth_info_test() {
        let id_auth_info_path = get_test_path("auth_info.b64");
        let id_auth_info_b64 = fs::read(id_auth_info_path.as_path())
            .expect("failed to read: 'auth_info.b64'");
        let id_auth_info_bytes = base64::decode(&id_auth_info_b64[..])
            .expect("failed to decode: 'auth_info.b64' as base64");

        let id_auth_info: &IdAuthInfo = try_from_bytes(&id_auth_info_bytes[..])
            .expect("failed to decode 'auth_info.b64' as an IdBlock");

        assert_eq!(id_auth_info.id_key_algo, 1);
        assert_eq!(id_auth_info.author_key_algo, 1);
        unsafe {
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.bytes), "776aaace68af45d6c1ceaf64523b748e42f8c171ce5f22237d40e50595870c887552f8fac0b9605bb53fc059488b2154000000000000000000000000000000000000000000000000b9fd80ad8eecb48624b919002f0a3181643c1b23edb83488d243e1d8044b5e3ba7a5c8caabf72cc551c4fadab983c73e000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.r), "776aaace68af45d6c1ceaf64523b748e42f8c171ce5f22237d40e50595870c887552f8fac0b9605bb53fc059488b2154000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_block_sig.body.s), "b9fd80ad8eecb48624b919002f0a3181643c1b23edb83488d243e1d8044b5e3ba7a5c8caabf72cc551c4fadab983c73e000000000000000000000000000000000000000000000000");
            assert_eq!(id_auth_info.id_pubkey.curve, 2);
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.bytes), "485215abb30f7a2f89794c0ae30345ea3846c5439d6ff89265ea862505be7bc2e4d642c2f94a6c1b813ffd66fb21ff640000000000000000000000000000000000000000000000001cbfe7e621c1a7ff0c8baadff28b26330e713ddd0e8f3921d5fa3ea63ee180f6c92a6367aad3e4c48482f1d961a61503000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.body.qx), "485215abb30f7a2f89794c0ae30345ea3846c5439d6ff89265ea862505be7bc2e4d642c2f94a6c1b813ffd66fb21ff64000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_pubkey.inner.body.qy), "1cbfe7e621c1a7ff0c8baadff28b26330e713ddd0e8f3921d5fa3ea63ee180f6c92a6367aad3e4c48482f1d961a61503000000000000000000000000000000000000000000000000");
        }
        unsafe {
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.bytes), "21d3672ab8ef8a86fb1a979fb169bc1f238aab8f194f27b8122b5da519585e90a11a1522851ebb6b710b88298eae5e83000000000000000000000000000000000000000000000000da05badeda8b5c0dc9125e2ee608dc40238460c27bfa55e43e3be785aec90a782d7f35ef7d4b42cad8acfe454ac933ab000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.r), "21d3672ab8ef8a86fb1a979fb169bc1f238aab8f194f27b8122b5da519585e90a11a1522851ebb6b710b88298eae5e83000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.id_key_sig.body.s), "da05badeda8b5c0dc9125e2ee608dc40238460c27bfa55e43e3be785aec90a782d7f35ef7d4b42cad8acfe454ac933ab000000000000000000000000000000000000000000000000");
            assert_eq!(id_auth_info.id_pubkey.curve, 2);
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.bytes), "3441ad9a5aa58abf5416d6ae05d6527feb1eb0ee8c86898f43c6be011239dd7f0c3ccec59c89e323b8f3fa1ef5a2ba0a0000000000000000000000000000000000000000000000003d7de26dd160f0431a2ccb1f7ac0f1c983dfdb46ca86d5b2dba1b0b54b7802ed4dd8fa68ca333ad7ab0d3c50294226a3000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.body.qx), "3441ad9a5aa58abf5416d6ae05d6527feb1eb0ee8c86898f43c6be011239dd7f0c3ccec59c89e323b8f3fa1ef5a2ba0a000000000000000000000000000000000000000000000000");
            assert_eq!(fmt_slice_vec_to_hex(&id_auth_info.author_pubkey.inner.body.qy), "3d7de26dd160f0431a2ccb1f7ac0f1c983dfdb46ca86d5b2dba1b0b54b7802ed4dd8fa68ca333ad7ab0d3c50294226a3000000000000000000000000000000000000000000000000");
        }

        assert_eq!(id_auth_info.to_base64().unwrap(), String::from_utf8(id_auth_info_b64).unwrap());
    }

    // Util
    fn get_test_path(path: &str) -> PathBuf {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(RESOURCES_TEST_DIR);
        test_path.push(path);
        test_path
    }
}