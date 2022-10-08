use std::os::unix::io::AsRawFd;
use async_std::fs::File;
use async_std::io::WriteExt;
use async_std::path::Path;
use bytes::Bytes;

pub async fn write_bytes_to_file(file: &Path, bytes: &Bytes) -> crate::error::Result<()> {
    let mut output = File::create(&file).await
        .map_err(|e| crate::error::io(e, Some(format!("failed to create file: {}",
                                                      file.to_str().unwrap()))))?;

    output.write_all(bytes).await
        .map_err(|e| crate::error::io(e, Some(format!("failed to write to file: {}",
                                                      file.to_str().unwrap()))))?;

    Ok(())
}

pub fn flock(file: &File, flag: libc::c_int) -> crate::error::Result<()> {
    let ret = unsafe {
        libc::flock(file.as_raw_fd(), flag)
    };
    if ret < 0 {
        Err(crate::error::io(std::io::Error::last_os_error(), None))
    } else {
        Ok(())
    }
}