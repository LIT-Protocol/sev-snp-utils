use std::io::Read;
use bytemuck::{Pod, Zeroable};
use libc::{c_uchar, c_uint, c_ulonglong};
use once_cell::sync::Lazy;

use crate::error::{conversion, map_io_err, Result, validation};

pub(crate) const ID_BLK_DIGEST_BITS: usize = 384;
pub(crate) const ID_BLK_DIGEST_BYTES: usize = ID_BLK_DIGEST_BITS / 8;

pub(crate) const ID_BLK_FAMILY_ID_BITS: usize = 128;
pub(crate) const ID_BLK_FAMILY_ID_BYTES: usize = ID_BLK_FAMILY_ID_BITS / 8;

pub(crate) const ID_BLK_IMAGE_ID_BITS: usize = 128;
pub(crate) const ID_BLK_IMAGE_ID_BYTES: usize = ID_BLK_IMAGE_ID_BITS / 8;

pub(crate) const ID_BLK_VERSION: usize = 1;

const ID_AUTH_INFO_RESERVED1_BYTES: usize = 0x03F - 0x008 + 1;
const ID_AUTH_INFO_RESERVED2_BYTES: usize = 0x67F - 0x644 + 1;
const ID_AUTH_INFO_RESERVED3_BYTES: usize = 0xFFF - 0xC84 + 1;

const ECDSA_POINT_SIZE_BITS: usize = 576;
const ECDSA_POINT_SIZE: usize = ECDSA_POINT_SIZE_BITS / 8;
const ECDSA_PUBKEY_RSVD_SIZE: usize = 0x403 - 0x94 + 1;
const ECDSA_SIG_RSVD_SIZE: usize = 0x1ff - 0x90 + 1;
const ECDSA_PUBKEY_SIZE: usize = 0x404;
const ECDSA_SIG_SIZE: usize = 0x200;

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
    pub fn new(ld: LaunchDigest,
               family_id: FamilyId,
               image_id: ImageId,
               version: u32,
               guest_svn: u32,
               policy: u64) -> Self {
        Self {
            ld,
            family_id,
            image_id,
            version,
            guest_svn,
            policy,
        }
    }
}

unsafe impl Zeroable for IdBlock {}

unsafe impl Pod for IdBlock {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdAuthInfo {
    id_key_algo: c_uint,
    author_key_algo: c_uint,
    reserved1: [c_uchar; ID_AUTH_INFO_RESERVED1_BYTES],
    id_block_sig: SevEcdsaSig,
    id_pubkey: SevEcdsaPubKey,
    reserved2: [c_uchar; ID_AUTH_INFO_RESERVED2_BYTES],
    id_key_sig: SevEcdsaSig,
    author_pubkey: SevEcdsaPubKey,
    reserved3: [c_uchar; ID_AUTH_INFO_RESERVED3_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SevEcdsaSig {
    body: SevEcdsaSigBody,
    bytes: [c_uchar; 2 * ECDSA_POINT_SIZE],
}

unsafe impl Zeroable for SevEcdsaSig {}

unsafe impl Pod for SevEcdsaSig {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaSigBody {
    r: [c_uchar; ECDSA_POINT_SIZE],
    s: [c_uchar; ECDSA_POINT_SIZE],
    reserved: [c_uchar; ECDSA_SIG_RSVD_SIZE],
}

unsafe impl Zeroable for SevEcdsaSigBody {}

unsafe impl Pod for SevEcdsaSigBody {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaPubKey {
    curve: c_uint,
    inner: SevEcdsaPubKeyInner,
}

unsafe impl Zeroable for SevEcdsaPubKey {}

unsafe impl Pod for SevEcdsaPubKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SevEcdsaPubKeyInner {
    body: SevEcdsaPubKeyBody,
    bytes: [c_uchar; 2 * ECDSA_POINT_SIZE],
}

unsafe impl Zeroable for SevEcdsaPubKeyInner {}

unsafe impl Pod for SevEcdsaPubKeyInner {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SevEcdsaPubKeyBody {
    qx: [c_uchar; ECDSA_POINT_SIZE],
    qy: [c_uchar; ECDSA_POINT_SIZE],
    reserved: [c_uchar; ECDSA_PUBKEY_RSVD_SIZE],
}

unsafe impl Zeroable for SevEcdsaPubKeyBody {}

unsafe impl Pod for SevEcdsaPubKeyBody {}