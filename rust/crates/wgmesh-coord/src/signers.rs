//! Hot-reloadable allowlist of agent identities (ed25519 SSH pubkeys).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::info;
use wgmesh_core::sig;

#[derive(Debug, Error)]
pub enum SignersError {
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}:{line}: {msg}")]
    BadLine {
        path: String,
        line: usize,
        msg: String,
    },
}

/// Cheap-to-clone handle (Arc inside).
#[derive(Debug, Clone)]
pub struct Signers {
    inner: Arc<RwLock<HashMap<String, String>>>,
    path: String,
}

impl Signers {
    pub fn load(path: &str) -> Result<Self, SignersError> {
        let s = Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            path: path.to_string(),
        };
        s.reload()?;
        Ok(s)
    }

    pub fn reload(&self) -> Result<(), SignersError> {
        let data = std::fs::read_to_string(&self.path).map_err(|e| SignersError::Io {
            path: self.path.clone(),
            source: e,
        })?;
        let mut new = HashMap::new();
        for (i, raw_line) in data.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let raw = sig::ed_pub_b64_from_authorized_line(line).map_err(|e| {
                SignersError::BadLine {
                    path: self.path.clone(),
                    line: i + 1,
                    msg: e.to_string(),
                }
            })?;
            // Comment after the base64 blob is the third whitespace field, optional.
            let comment: String = line.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
            new.insert(raw, comment);
        }
        let count = new.len();
        *self.inner.write().unwrap() = new;
        info!(count, path = %self.path, "authorized_signers loaded");
        Ok(())
    }

    pub fn contains(&self, ed_pub_b64: &str) -> bool {
        self.inner.read().unwrap().contains_key(ed_pub_b64)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}
