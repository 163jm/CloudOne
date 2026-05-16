use anyhow::Result;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use std::{path::Path, sync::Arc, time::SystemTime};

use crate::types::{AppState, FileInfo, Settings, ShareLink, User};
use crate::util::{is_danger_path, normalize_path, ok_json, json_error};

pub async fn init_db(db: &SqlitePool) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, token_version INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY AUTOINCREMENT, storage_dir TEXT, lang TEXT, ui_theme TEXT DEFAULT '', ui_font TEXT DEFAULT '', editor_font TEXT DEFAULT '', webdav_enabled BOOLEAN DEFAULT 0, webdav_sub_path TEXT DEFAULT '', webdav_username TEXT DEFAULT '', webdav_password_enc TEXT DEFAULT '', jwt_secret_enc TEXT DEFAULT '', show_hidden BOOLEAN DEFAULT 0)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS share_links (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, file_path TEXT, is_dir BOOLEAN, user_id INTEGER, expires_at TEXT NULL, max_views INTEGER DEFAULT 0, view_count INTEGER DEFAULT 0, created_at TEXT)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS file_visibilities (id INTEGER PRIMARY KEY AUTOINCREMENT, file_path TEXT UNIQUE, is_public BOOLEAN)").execute(db).await?;
    let cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
        .fetch_one(db)
        .await?;
    if cnt == 0 {
        sqlx::query(
            "INSERT INTO settings (id, storage_dir, lang) VALUES (1, './data/storage', 'zh')",
        )
        .execute(db)
        .await?;
    }
    Ok(())
}

pub async fn get_settings(db: &SqlitePool) -> Result<Settings> {
    let r = sqlx::query("SELECT * FROM settings ORDER BY id LIMIT 1")
        .fetch_one(db)
        .await?;
    Ok(Settings {
        id: r.get("id"),
        storage_dir: r.try_get("storage_dir").unwrap_or_default(),
        lang: r.try_get("lang").unwrap_or_else(|_| "zh".into()),
        ui_theme: r.try_get("ui_theme").unwrap_or_default(),
        ui_font: r.try_get("ui_font").unwrap_or_default(),
        editor_font: r.try_get("editor_font").unwrap_or_default(),
        webdav_enabled: r.try_get::<i64, _>("webdav_enabled").unwrap_or(0) != 0,
        webdav_sub_path: r.try_get("webdav_sub_path").unwrap_or_default(),
        webdav_username: r.try_get("webdav_username").unwrap_or_default(),
        webdav_password_enc: r.try_get("webdav_password_enc").unwrap_or_default(),
        jwt_secret_enc: r.try_get("jwt_secret_enc").unwrap_or_default(),
        show_hidden: r.try_get::<i64, _>("show_hidden").unwrap_or(0) != 0,
    })
}

pub async fn update_setting_storage(db: &SqlitePool, s: &str) -> Result<()> {
    sqlx::query("UPDATE settings SET storage_dir=? WHERE id=1")
        .bind(s)
        .execute(db)
        .await?;
    Ok(())
}

pub fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: r.get("id"),
        username: r.get("username"),
        password: r.get("password"),
        token_version: r.try_get("token_version").unwrap_or(0),
        created_at: r.try_get("created_at").unwrap_or_default(),
        updated_at: r.try_get("updated_at").unwrap_or_default(),
    })
}

pub async fn get_user_by_id(db: &SqlitePool, id: i64) -> Result<User> {
    row_to_user(
        sqlx::query("SELECT * FROM users WHERE id=?")
            .bind(id)
            .fetch_one(db)
            .await?,
    )
}

pub fn row_to_share(r: sqlx::sqlite::SqliteRow) -> Result<ShareLink> {
    Ok(ShareLink {
        id: r.get("id"),
        code: r.get("code"),
        file_path: r.get("file_path"),
        is_dir: r.get::<i64, _>("is_dir") != 0,
        user_id: r.get("user_id"),
        expires_at: r.try_get("expires_at").ok(),
        max_views: r.try_get("max_views").unwrap_or(0),
        view_count: r.try_get("view_count").unwrap_or(0),
        created_at: r.try_get("created_at").unwrap_or_default(),
    })
}

pub async fn get_share_by_id(db: &SqlitePool, id: i64) -> Result<ShareLink> {
    row_to_share(
        sqlx::query("SELECT * FROM share_links WHERE id=?")
            .bind(id)
            .fetch_one(db)
            .await?,
    )
}

pub async fn get_share(db: &SqlitePool, code: &str, count: bool) -> Result<ShareLink> {
    let row = sqlx::query("SELECT * FROM share_links WHERE code=?")
        .bind(code)
        .fetch_one(db)
        .await?;
    let mut l = row_to_share(row)?;
    if let Some(e) = &l.expires_at {
        if DateTime::parse_from_rfc3339(e)
            .map(|d| d.with_timezone(&Utc) < Utc::now())
            .unwrap_or(false)
        {
            return Err(anyhow::anyhow!("share link has expired"));
        }
    }
    if l.max_views > 0 && l.view_count >= l.max_views {
        return Err(anyhow::anyhow!("share link has reached maximum views"));
    }
    if count {
        l.view_count += 1;
        let _ = sqlx::query("UPDATE share_links SET view_count=? WHERE id=?")
            .bind(l.view_count)
            .bind(l.id)
            .execute(db)
            .await;
    }
    Ok(l)
}

pub async fn is_public(db: &SqlitePool, rel: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM file_visibilities WHERE file_path=? AND is_public=1",
    )
    .bind(normalize_path(rel))
    .fetch_one(db)
    .await
    .unwrap_or(0)
        > 0
}

pub async fn upsert_visibility(db: &SqlitePool, rel: &str, public: bool) -> Result<()> {
    sqlx::query("INSERT INTO file_visibilities (file_path,is_public) VALUES (?,?) ON CONFLICT(file_path) DO UPDATE SET is_public=excluded.is_public")
        .bind(normalize_path(rel))
        .bind(public as i64)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_visibility_tree(db: &SqlitePool, rel: &str) {
    let n = normalize_path(rel);
    let pat = format!("{n}/%");
    let _ = sqlx::query("DELETE FROM file_visibilities WHERE file_path=? OR file_path LIKE ?")
        .bind(n)
        .bind(pat)
        .execute(db)
        .await;
}

pub async fn migrate_visibility(db: &SqlitePool, src: &str, dst: &str) {
    copy_visibility(db, src, dst).await;
    delete_visibility_tree(db, src).await;
}

pub async fn copy_visibility(db: &SqlitePool, src: &str, dst: &str) {
    let sn = normalize_path(src);
    let dn = normalize_path(dst);
    let pat = format!("{sn}/%");
    if let Ok(rows) = sqlx::query(
        "SELECT file_path,is_public FROM file_visibilities WHERE file_path=? OR file_path LIKE ?",
    )
    .bind(&sn)
    .bind(&pat)
    .fetch_all(db)
    .await
    {
        for r in rows {
            let old: String = r.get(0);
            let pubv: i64 = r.get(1);
            let newp = if old == sn {
                dn.clone()
            } else {
                format!("{}{}", dn, old.trim_start_matches(&sn as &str))
            };
            let _ = upsert_visibility(db, &newp, pubv != 0).await;
        }
    }
}

pub async fn file_info(db: &SqlitePool, abs: &Path, rel: &str) -> Result<FileInfo> {
    let md = tokio::fs::metadata(abs).await?;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    let mode = md.permissions().mode();
    #[cfg(not(unix))]
    let mode = 0u32;
    Ok(FileInfo {
        name: Path::new(rel)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        path: normalize_path(rel),
        is_dir: md.is_dir(),
        size: if md.is_dir() { 0 } else { md.len() },
        mod_time: DateTime::<Utc>::from(md.modified().unwrap_or(SystemTime::now())).to_rfc3339(),
        is_public: is_public(db, rel).await,
        mode,
    })
}

pub async fn list_dir(state: &AppState, rel: &str) -> Result<Vec<FileInfo>> {
    use std::collections::HashMap;
    let settings = get_settings(&state.db).await?;
    let show_hidden = settings.show_hidden;
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    let mut rd = tokio::fs::read_dir(&abs).await?;
    let base = normalize_path(rel);

    let mut entries: Vec<(std::path::PathBuf, String)> = Vec::new();
    while let Some(e) = rd.next_entry().await? {
        let p = e.path();
        if is_danger_path(&p) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let child = normalize_path(&format!("{}/{}", base, name));
        entries.push((p, child));
    }

    // 批量查询可见性，避免 N+1
    let child_paths: Vec<String> = entries.iter().map(|(_, c)| c.clone()).collect();
    let mut vis_map: HashMap<String, bool> = HashMap::new();
    if !child_paths.is_empty() {
        let placeholders = child_paths.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query_str = format!(
            "SELECT file_path FROM file_visibilities WHERE is_public=1 AND file_path IN ({})",
            placeholders
        );
        let mut q = sqlx::query(&query_str);
        for p in &child_paths {
            q = q.bind(p);
        }
        if let Ok(rows) = q.fetch_all(&state.db).await {
            for row in rows {
                let fp: String = row.get(0);
                vis_map.insert(fp, true);
            }
        }
    }

    let mut out = Vec::new();
    for (p, child) in entries {
        let abs_p = p.clone();
        let meta = tokio::task::spawn_blocking(move || std::fs::metadata(&abs_p)).await;
        if let Ok(Ok(md)) = meta {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(unix)]
            let mode = md.permissions().mode();
            #[cfg(not(unix))]
            let mode = 0u32;
            let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            out.push(FileInfo {
                name,
                path: child.clone(),
                is_dir: md.is_dir(),
                size: if md.is_dir() { 0 } else { md.len() },
                mod_time: DateTime::<Utc>::from(
                    md.modified().unwrap_or(SystemTime::now()),
                )
                .to_rfc3339(),
                is_public: *vis_map.get(&child).unwrap_or(&false),
                mode,
            });
        }
    }
    Ok(out)
}
