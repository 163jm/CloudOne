use anyhow::Result;
use axum::{Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::{Value, json};
use std::{ffi::OsStr, net::IpAddr, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
use chrono::Utc;

pub fn json_error(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({"error": msg.to_string()}))).into_response()
}

pub fn ok_json(v: Value) -> Response {
    Json(v).into_response()
}

pub fn now_string() -> String {
    Utc::now().to_rfc3339()
}

pub fn unix_now() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize
}

pub fn normalize_path(p: &str) -> String {
    let trimmed = p.trim_start_matches('/');
    if trimmed.is_empty() {
        return "/".into();
    }
    let mut out = PathBuf::from("/");
    for c in Path::new(trimmed).components() {
        if let std::path::Component::Normal(v) = c {
            out.push(v);
        }
    }
    let s = out.to_string_lossy().replace('\\', "/");
    if s.is_empty() { "/".into() } else { s }
}

pub fn is_danger_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    ["/proc", "/sys", "/dev"]
        .iter()
        .any(|x| s == *x || s.starts_with(&format!("{x}/")))
}

pub fn safe_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .unwrap_or_else(|| OsStr::new("download"))
        .to_string_lossy()
        .to_string()
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified()
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || ((v.segments()[0] & 0xfe00) == 0xfc00)
                || ((v.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

pub fn real_ip(headers: &axum::http::HeaderMap, addr: std::net::SocketAddr) -> String {
    let remote = addr.ip();
    if !is_private_ip(remote) {
        return remote.to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| remote.to_string())
        })
}

/// AES-256-GCM 加密
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String> {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    use base64::{Engine as _, engine::general_purpose};
    use rand::RngCore;
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(general_purpose::STANDARD.encode(out))
}

/// AES-256-GCM 解密，失败返回 None
pub fn decrypt_opt(key: &[u8; 32], enc: &str) -> Option<String> {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    use base64::{Engine as _, engine::general_purpose};
    if enc.is_empty() {
        return Some(String::new());
    }
    let data = general_purpose::STANDARD.decode(enc).ok()?;
    if data.len() < 12 {
        return None;
    }
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .ok()?;
    String::from_utf8(pt).ok()
}

pub fn copy_path(src: &Path, dst: &Path) -> std::io::Result<()> {
    let md = std::fs::metadata(src)?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            copy_path(&e.path(), &dst.join(e.file_name()))?;
        }
    } else {
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}
