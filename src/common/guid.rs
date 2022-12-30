use uuid::Uuid;

use crate::error::{conversion, Result};

pub fn guid_le_to_slice(guid: &str) -> Result<[u8; 16]> {
    let guid = Uuid::try_from(guid)
        .map_err(|e| conversion(e, None))?;
    let guid = guid.to_bytes_le();
    let guid = guid.as_slice();

    guid.try_into()
        .map_err(|e| conversion(e, None))
}