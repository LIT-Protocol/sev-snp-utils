use sha2::{Digest, Sha384};
use sha2::digest::Output;

pub fn sha384(data: impl AsRef<[u8]>) -> Output<Sha384> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}
