use async_trait::async_trait;
use std::path::PathBuf;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform error: {0}")]
    Platform(String),
}

#[async_trait]
pub trait SecureKeyStore: Send + Sync {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), KeyStoreError>;
    async fn retrieve(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, KeyStoreError>;
    async fn delete(&self, key: &str) -> Result<(), KeyStoreError>;
}

/// Development / Linux fallback: mode-0600 files under a directory.
/// Not for production private keys on multi-user hosts.
pub struct FileKeyStore {
    root: PathBuf,
}

impl FileKeyStore {
    pub fn new(root: PathBuf) -> Result<Self, KeyStoreError> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let safe = key.replace(['/', '\\', ':'], "_");
        self.root.join(safe)
    }
}

#[async_trait]
impl SecureKeyStore for FileKeyStore {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), KeyStoreError> {
        let path = self.path_for(key);
        tokio::fs::write(&path, value).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        let path = self.path_for(key);
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|_| KeyStoreError::NotFound(key.to_string()))?;
        Ok(Zeroizing::new(bytes))
    }

    async fn delete(&self, key: &str) -> Result<(), KeyStoreError> {
        let path = self.path_for(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const SERVICE: &str = "io.wsl.zerotrust.vpn";

    pub struct KeychainStore;

    #[async_trait]
    impl SecureKeyStore for KeychainStore {
        async fn store(&self, key: &str, value: &[u8]) -> Result<(), KeyStoreError> {
            let key = key.to_string();
            let value = value.to_vec();
            tokio::task::spawn_blocking(move || {
                let _ = delete_generic_password(SERVICE, &key);
                set_generic_password(SERVICE, &key, &value)
                    .map_err(|e| KeyStoreError::Platform(e.to_string()))
            })
            .await
            .map_err(|e| KeyStoreError::Platform(e.to_string()))?
        }

        async fn retrieve(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
            let key = key.to_string();
            let bytes = tokio::task::spawn_blocking(move || {
                get_generic_password(SERVICE, &key)
                    .map_err(|_| KeyStoreError::NotFound(key.clone()))
            })
            .await
            .map_err(|e| KeyStoreError::Platform(e.to_string()))??;
            Ok(Zeroizing::new(bytes))
        }

        async fn delete(&self, key: &str) -> Result<(), KeyStoreError> {
            let key = key.to_string();
            tokio::task::spawn_blocking(move || match delete_generic_password(SERVICE, &key) {
                Ok(()) => Ok(()),
                Err(_) => Ok(()),
            })
            .await
            .map_err(|e| KeyStoreError::Platform(e.to_string()))?
        }
    }
}
