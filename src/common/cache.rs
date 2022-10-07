use std::env;

use async_std::fs;
use async_std::path::{Path, PathBuf};

use crate::common::env::{ENV_CACHE_PATH_DEFAULT, ENV_CACHE_PATH_KEY};

pub async fn cache_file_path(path: &str, create_dir: bool) -> PathBuf {
    let cache_file = PathBuf::from(format!("{}/{}",
                                           env::var(ENV_CACHE_PATH_KEY)
                                               .unwrap_or(ENV_CACHE_PATH_DEFAULT.to_string()),
                                           path));

    if create_dir {
        if let Some(parent) = cache_file.parent() {
            cache_create_path_or_panic(parent).await;
        }
    }

    cache_file
}

pub async fn cache_dir_path(path: &str, create: bool) -> PathBuf {
    let cache_path = PathBuf::from(format!("{}/{}",
                                           env::var(ENV_CACHE_PATH_KEY)
                                               .unwrap_or(ENV_CACHE_PATH_DEFAULT.to_string()),
                                           path));

    if create {
        cache_create_path_or_panic(cache_path.as_path()).await;
    }

    cache_path
}

async fn cache_create_path_or_panic(cache_path: &Path) {
    if !cache_path.exists().await {
        fs::create_dir_all(&cache_path).await
            .expect(format!("failed to create cache dir: {} \
                (hint: you can change the path by setting {})",
                            cache_path.to_str().unwrap(), ENV_CACHE_PATH_KEY).as_str());
    }
}