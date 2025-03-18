use std::time::Duration;

use async_std::fs::File;
use async_std::io::WriteExt;
use async_std::path::PathBuf;
use async_std::{fs, task};
use bytes::Bytes;
use reqwest::Client;
use tokio::sync::Mutex;
use tracing::{trace, warn};

use crate::common::cache::cache_file_path;
use crate::error;

static FETCH_LOCK: Mutex<()> = Mutex::const_new(());

pub async fn fetch_url(
    url: &str,
    attempts: u8,
    retry_sleep_ms: u64,
    retry_sleep_exponent_ms: u64,
) -> error::Result<Option<Bytes>> {
    trace!(
        "fetch_url: url: {}, attempts: {}, retry_sleep_ms: {}, retry_sleep_exponent_ms: {}",
        url,
        attempts,
        retry_sleep_ms,
        retry_sleep_exponent_ms
    );

    let _guard = tokio::time::timeout(Duration::from_secs(10), FETCH_LOCK.lock())
        .await
        .map_err(|e| {
            error::lock_timeout(
                e,
                Some("failed to acquire fetch lock in 10 seconds".to_string()),
            )
        })?;

    let client = create_http_client()?;

    let mut body: Option<Bytes> = None;
    let mut retry_sleep_ms = retry_sleep_ms;
    for attempt in 0..attempts {
        let is_last = attempt >= attempts - 1;
        let mut err_msg: String;

        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    err_msg = format!("failed to read bytes during fetch: {}", &url);
                    let bytes = response
                        .bytes()
                        .await
                        .map_err(|e| error::fetch(e, Some(err_msg)))?;

                    if bytes.len() > 0 {
                        body = Some(bytes);
                        break;
                    } else {
                        err_msg = format!("failed to fetch URL '{}', empty response", url);
                    }
                } else {
                    err_msg = format!(
                        "failed to fetch URL '{}', status: {}",
                        url,
                        response.status()
                    );
                    let headers = response.headers();
                    if let Some(retry_interval_value) = headers.get("retry-after") {
                        // Try retrieve the value from the headers
                        if let Ok(retry_interval_str) = retry_interval_value.to_str() {
                            // Parse value as string
                            if let Ok(retry_interval_seconds) = retry_interval_str.parse::<u64>() {
                                // Override the existing retry_sleep with the value given by AMD
                                // Note: original logic will still be applied on next pass if AMD doesn't provide a value.
                                retry_sleep_ms = retry_interval_seconds * 1000;
                                if retry_sleep_ms >= 1_000 {
                                    warn!("AMD is requesting a retry interval of over 1 second.")
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                err_msg = format!("failed to fetch URL '{}': {:?}", url, err);
            }
        }

        if is_last {
            return Err(error::fetch(err_msg, None));
        }

        trace!(
            "{} (attempt {} of {}) waiting for {}ms",
            &err_msg,
            attempt + 1,
            attempts,
            retry_sleep_ms
        );

        task::sleep(Duration::from_millis(retry_sleep_ms)).await;
        retry_sleep_ms = retry_sleep_ms * retry_sleep_exponent_ms / 1000;
    }

    Ok(body)
}

pub async fn fetch_url_cached(
    url: &str,
    path: &str,
    attempts: u8,
    retry_sleep_ms: u64,
    retry_sleep_exponent_ms: u64,
) -> error::Result<Bytes> {
    trace!("fetch_url_cached: url: {}, path: {}", url, path);
    let full_path = cache_file_path(path, true).await;
    if full_path.exists().await {
        return read_cached_file(full_path).await;
    }

    match fetch_url(url, attempts, retry_sleep_ms, retry_sleep_exponent_ms).await? {
        Some(body) => {
            let mut output = File::create(&full_path).await.map_err(|e| {
                crate::error::io(
                    e,
                    Some(format!(
                        "failed to create cache file: {}",
                        full_path.to_str().unwrap()
                    )),
                )
            })?;

            output.write_all(body.as_ref()).await.map_err(|e| {
                crate::error::io(
                    e,
                    Some(format!(
                        "failed to write to cache file: {}",
                        full_path.to_str().unwrap()
                    )),
                )
            })?;

            Ok(body)
        }
        None => Err(crate::error::fetch(
            "Nothing fetched (retries exhausted?)",
            None,
        )),
    }
}

async fn read_cached_file(full_path: PathBuf) -> error::Result<Bytes> {
    match fs::read(&full_path).await {
        Ok(buf) => Ok(Bytes::from(buf)),
        Err(e) => Err(crate::error::io(
            e,
            Some(format!(
                "failed to read cached file: {}",
                full_path.to_str().unwrap()
            )),
        )),
    }
}

#[cfg(feature = "trust-dns")]
fn create_http_client() -> error::Result<Client> {
    let mut client = Client::builder().timeout(Duration::from_secs(60));
    client = client.trust_dns(true);

    let client = client
        .build()
        .map_err(|e| error::fetch(e, Some("failed to construct reqwest client".into())))?;

    Ok(client)
}

#[cfg(not(feature = "trust-dns"))]
fn create_http_client() -> error::Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| error::fetch(e, Some("failed to construct reqwest client".into())))?;

    Ok(client)
}
