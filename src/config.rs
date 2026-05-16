use anyhow::Result;
use std::path::Path;
use tokio::fs;

pub async fn ensure_conf(data: &Path) -> Result<()> {
    let p = data.join("conf.ini");
    if !p.exists() {
        fs::write(p, "[server]\nhost=0.0.0.0\nport=6677\n").await?;
    }
    Ok(())
}

pub async fn load_conf(data: &Path) -> Result<(String, String)> {
    let s = fs::read_to_string(data.join("conf.ini"))
        .await
        .unwrap_or_default();
    let mut host = "0.0.0.0".to_string();
    let mut port = "6677".to_string();
    let mut section = String::new();
    for l in s.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].trim().to_lowercase();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        let v = if let Some(idx) = v.find(" #") {
            v[..idx].trim()
        } else {
            v
        };
        match (section.as_str(), k) {
            ("server", "host") => host = v.to_string(),
            ("server", "port") => port = v.to_string(),
            _ => {}
        }
    }
    Ok((host, port))
}
