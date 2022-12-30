use std::fs::File;
use std::io;
use std::path::Path;
use sha2::{Digest, Sha384, Sha256};
use sha2::digest::Output;

use crate::error::{io, Result};

pub fn sha384(data: impl AsRef<[u8]>) -> Output<Sha384> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn sha256_file(file_path: &Path) -> Result<Output<Sha256>> {
    let mut hasher = Sha256::new();
    let mut file = File::open(file_path)
        .map_err(|e| io(e, None))?;

    let _ = io::copy(&mut file, &mut hasher)
        .map_err(|e| io(e, None))?;
    Ok(hasher.finalize())
}

pub fn sha256(data: impl AsRef<[u8]>) -> Output<Sha256> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}
