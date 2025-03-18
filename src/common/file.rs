use async_std::fs::File;
use async_std::io::WriteExt;
use async_std::path::Path;
use bytes::Bytes;

pub async fn write_bytes_to_file(file: &Path, bytes: &Bytes) -> crate::error::Result<()> {
    let mut output = File::create(&file).await.map_err(|e| {
        crate::error::io(
            e,
            Some(format!("failed to create file: {}", file.to_str().unwrap())),
        )
    })?;

    output.write_all(bytes).await.map_err(|e| {
        crate::error::io(
            e,
            Some(format!(
                "failed to write to file: {}",
                file.to_str().unwrap()
            )),
        )
    })?;

    Ok(())
}
