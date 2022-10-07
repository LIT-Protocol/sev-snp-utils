use std::time::Duration;

use async_std::{fs, task};
use async_std::fs::File;
use async_std::io::WriteExt;
use bytes::Bytes;
use log::{debug, warn};

use crate::common::cache::{cache_file_path};

pub async fn fetch_url(url: &str,
                       attempts: u8, retry_sleep_ms: u64) -> crate::error::Result<Option<Bytes>> {
    let mut body: Option<Bytes> = None;
    for attempt in 0..attempts {
        let is_last = attempt >= attempts - 1;

        match reqwest::get(url).await {
            Ok(response) => {
                if response.status().is_success() {
                    let err_msg = format!("failed to read bytes during fetch: {}", &url);

                    body = Some(
                        response.bytes().await
                            .map_err(|e|
                                crate::error::fetch(e, Some(err_msg)))?
                    );
                    break;
                } else {
                    let err_msg = format!("failed to fetch URL '{}', status: {}",
                                          url, response.status());
                    if is_last {
                        return Err(crate::error::fetch(err_msg, None));
                    } else {
                        debug!("{}", &err_msg);
                    }
                }
            }
            Err(err) => {
                let err_msg = format!("failed to fetch URL '{}': {:?}", url, err);

                if is_last {
                    return Err(crate::error::fetch(err, Some(err_msg)));
                } else {
                    warn!("{}", &err_msg);
                }
            }
        }

        task::sleep(Duration::from_millis(retry_sleep_ms)).await;
    }

    Ok(body)
}

pub async fn fetch_url_cached(url: &str, path: &str,
                              attempts: u8, retry_sleep_ms: u64) -> crate::error::Result<Bytes> {
    let full_path = cache_file_path(path, true).await;

    if full_path.exists().await {
        return match fs::read(&full_path).await {
            Ok(buf) => Ok(Bytes::from(buf)),
            Err(e) => Err(crate::error::io(e, Some(format!("failed to read cached file: {}",
                                                           full_path.to_str().unwrap()))))
        };
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