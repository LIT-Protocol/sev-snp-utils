use std::time::Duration;

use async_std::{fs, task};
use async_std::fs::File;
use async_std::io::WriteExt;
use async_std::path::PathBuf;
use bytes::Bytes;
use log::debug;
use reqwest::Client;

use crate::common::cache::cache_file_path;
use crate::error;

pub async fn fetch_url(url: &str,
                       attempts: u8, retry_sleep_ms: u64) -> error::Result<Option<Bytes>> {
    let client = create_http_client()?;

    let mut body: Option<Bytes> = None;
    for attempt in 0..attempts {
        let is_last = attempt >= attempts - 1;
        let mut err_msg: String;

        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    err_msg = format!("failed to read bytes during fetch: {}", &url);
                    let bytes = response.bytes().await
                        .map_err(|e|
                            error::fetch(e, Some(err_msg)))?;

                    if bytes.len() > 0 {
                        body = Some(bytes);
                        break;
                    } else {
                        err_msg = format!("failed to fetch URL '{}', empty response", url);
                    }
                } else {
                    err_msg = format!("failed to fetch URL '{}', status: {}",
                                      url, response.status());
                }
            }
            Err(err) => {
                err_msg = format!("failed to fetch URL '{}': {:?}", url, err);
            }
        }

        if is_last {
            return Err(error::fetch(err_msg, None));
        }

        debug!("{} (attempt {} of {})", &err_msg, attempt+1, attempts);

        task::sleep(Duration::from_millis(retry_sleep_ms)).await;
    }

    Ok(body)
}

pub async fn fetch_url_cached(url: &str, path: &str,
                              attempts: u8, retry_sleep_ms: u64) -> error::Result<Bytes> {
    let full_path = cache_file_path(path, true).await;
    if full_path.exists().await {
        return read_cached_file(full_path).await;
    }

    match fetch_url(url, attempts, retry_sleep_ms).await? {
        Some(body) => {
            let mut output = File::create(&full_path).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to create cache file: {}",
                                                              full_path.to_str().unwrap()))))?;

            output.write_all(body.as_ref()).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to write to cache file: {}",
                                                              full_path.to_str().unwrap()))))?;

            Ok(body)
        }
        None => Err(crate::error::fetch("Nothing fetched (retries exhausted?)", None))
    }
}

async fn read_cached_file(full_path: PathBuf) -> error::Result<Bytes> {
    match fs::read(&full_path).await {
        Ok(buf) => Ok(Bytes::from(buf)),
        Err(e) => Err(crate::error::io(e, Some(format!("failed to read cached file: {}",
                                                       full_path.to_str().unwrap()))))
    }
}

#[cfg(feature = "trust-dns")]
fn create_http_client() -> error::Result<Client> {
    let mut client = Client::builder();
    client = client.trust_dns(true);

    let client = client.build()
        .map_err(|e| error::fetch(e, Some("failed to construct reqwest client".into())))?;

    Ok(client)
}

#[cfg(not(feature = "trust-dns"))]
fn create_http_client() -> error::Result<Client> {
    let client = Client::builder().build()
        .map_err(|e| error::fetch(e, Some("failed to construct reqwest client".into())))?;

    Ok(client)
}