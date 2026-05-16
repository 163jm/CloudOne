use anyhow::anyhow;
use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path as AxPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::Utc;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use futures_util::StreamExt;
use rand::{Rng, RngCore, distributions::Alphanumeric};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tar::{Archive as TarArchive, Builder as TarBuilder};
use tokio::fs;
use tokio_util::io::ReaderStream;
use walkdir::WalkDir;
use axum::http::{HeaderValue, header};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::auth::req_user;
use crate::db::{
    copy_visibility, delete_visibility_tree, file_info, get_settings, get_share, get_share_by_id,
    is_public, list_dir, migrate_visibility, row_to_share, upsert_visibility,
};
use crate::types::{AppState, ShareLink};
use crate::util::{
    copy_path, is_private_ip, json_error, normalize_path, ok_json, safe_name,
};

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PathQuery {
    pub path: Option<String>,
    pub name: Option<String>,
    pub dir: Option<String>,
    pub subpath: Option<String>,
}

#[derive(Deserialize)]
pub struct OnePath {
    pub path: String,
    pub content: Option<String>,
    pub mode: Option<u32>,
}

#[derive(Deserialize)]
pub struct MoveReq {
    pub src: String,
    pub dst: String,
}

#[derive(Deserialize)]
pub struct BatchPaths {
    pub paths: Vec<String>,
    pub target: Option<String>,
    pub filename: Option<String>,
}

#[derive(Deserialize)]
pub struct VisReq {
    pub path: String,
    pub is_public: bool,
}

#[derive(Deserialize)]
pub struct ShareReq {
    pub path: String,
    pub is_dir: bool,
    pub expire_in: Option<i64>,
    pub max_views: Option<i64>,
}

#[derive(Deserialize)]
pub struct CompressReq {
    pub paths: Vec<String>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub dir: Option<String>,
}

#[derive(Deserialize)]
pub struct DecompressReq {
    pub path: String,
    pub dir: Option<String>,
}

#[derive(Deserialize)]
pub struct FetchReq {
    pub url: String,
    pub filename: Option<String>,
    pub dir: Option<String>,
}

#[derive(Deserialize)]
pub struct SettingsReq {
    pub storage_dir: Option<String>,
    pub lang: Option<String>,
    pub ui_theme: Option<String>,
    pub ui_font: Option<String>,
    pub editor_font: Option<String>,
    pub show_hidden: Option<bool>,
}

// ── Settings handlers ─────────────────────────────────────────────────────────

pub async fn get_settings_api(State(state): State<AppState>) -> Response {
    match get_settings(&state.db).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn update_settings(
    State(state): State<AppState>,
    Json(req): Json<SettingsReq>,
) -> Response {
    let mut s = get_settings(&state.db).await.unwrap();
    if let Some(d) = req.storage_dir.filter(|v| !v.is_empty()) {
        let clean = PathBuf::from(&d);
        let forbidden = [
            "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/boot", "/sys", "/proc", "/dev", "/run", "/var/run",
        ];
        let cs = clean.to_string_lossy();
        if forbidden.iter().any(|f| cs == *f || cs.starts_with(&format!("{f}/"))) {
            return json_error(StatusCode::BAD_REQUEST, "storage_dir points to a system directory");
        }
        if let Err(e) = fs::create_dir_all(&clean).await {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create storage dir: {e}"),
            );
        }
        s.storage_dir = d.clone();
        state.files.lock().await.set_root(clean);
    }
    if let Some(v) = req.lang.filter(|v| !v.is_empty()) { s.lang = v }
    if let Some(v) = req.ui_theme.filter(|v| !v.is_empty()) { s.ui_theme = v }
    if let Some(v) = req.ui_font.filter(|v| !v.is_empty()) { s.ui_font = v }
    if let Some(v) = req.editor_font.filter(|v| !v.is_empty()) { s.editor_font = v }
    if let Some(v) = req.show_hidden { s.show_hidden = v }
    sqlx::query("UPDATE settings SET storage_dir=?,lang=?,ui_theme=?,ui_font=?,editor_font=?,show_hidden=? WHERE id=?")
        .bind(&s.storage_dir).bind(&s.lang).bind(&s.ui_theme)
        .bind(&s.ui_font).bind(&s.editor_font).bind(s.show_hidden as i64).bind(s.id)
        .execute(&state.db).await.unwrap();
    Json(s).into_response()
}

// ── File handlers ─────────────────────────────────────────────────────────────

pub async fn list_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    match list_dir(&state, &p).await {
        Ok(v) => ok_json(json!({"files": v, "path": p})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn delete_file(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let Some(p) = q.path else {
        return json_error(StatusCode::BAD_REQUEST, "path is required");
    };
    if p == "/" || p.is_empty() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "cannot delete root directory");
    }
    let fm = state.files.lock().await.clone();
    match fm.safe_abs_path(&p).and_then(|abs| {
        std::fs::remove_dir_all(&abs)
            .or_else(|_| std::fs::remove_file(&abs))
            .map_err(Into::into)
    }) {
        Ok(_) => {
            delete_visibility_tree(&state.db, &p).await;
            ok_json(json!({"ok": true}))
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn write_rel(state: &AppState, rel: &str, data: impl AsRef<[u8]>) -> anyhow::Result<()> {
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    if let Some(p) = abs.parent() {
        fs::create_dir_all(p).await?;
    }
    fs::write(abs, data).await?;
    Ok(())
}

pub async fn upload_file(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
    mut mp: Multipart,
) -> Response {
    let dir = q.path.unwrap_or("/".into());
    let mut failed = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() != Some("files") { continue; }
        let name = field.file_name().map(|s| s.to_string()).unwrap_or_default();
        let safe = safe_name(&name);
        match field.bytes().await {
            Ok(b) => {
                if write_rel(&state, &format!("{dir}/{safe}"), b).await.is_err() {
                    failed.push(name)
                }
            }
            Err(_) => failed.push(name),
        }
    }
    if failed.is_empty() {
        ok_json(json!({"ok": true}))
    } else {
        (StatusCode::MULTI_STATUS, Json(json!({"ok": true, "failed": failed}))).into_response()
    }
}

pub async fn mkdir(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    let fm = state.files.lock().await.clone();
    match fm.safe_abs_path(&req.path).and_then(|p| std::fs::create_dir_all(p).map_err(Into::into)) {
        Ok(_) => ok_json(json!({"ok": true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn move_file(State(state): State<AppState>, Json(req): Json<MoveReq>) -> Response {
    move_one(&state, &req.src, &req.dst).await
}

pub async fn copy_file(State(state): State<AppState>, Json(req): Json<MoveReq>) -> Response {
    copy_one(&state, &req.src, &req.dst).await
}

async fn move_one(state: &AppState, src: &str, dst: &str) -> Response {
    let fm = state.files.lock().await.clone();
    match (fm.safe_abs_path(src), fm.safe_abs_path(dst)) {
        (Ok(s), Ok(d)) => match std::fs::rename(&s, &d) {
            Ok(_) => {
                migrate_visibility(&state.db, src, dst).await;
                ok_json(json!({"ok": true}))
            }
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        (Err(e), _) | (_, Err(e)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn copy_one(state: &AppState, src: &str, dst: &str) -> Response {
    let fm = state.files.lock().await.clone();
    match (fm.safe_abs_path(src), fm.safe_abs_path(dst)) {
        (Ok(s), Ok(d)) => match copy_path(&s, &d) {
            Ok(_) => {
                copy_visibility(&state.db, src, dst).await;
                ok_json(json!({"ok": true}))
            }
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        (Err(e), _) | (_, Err(e)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn download_file(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or_default();
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&p), true).await
}

pub async fn create_file(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    match write_rel(&state, &req.path, req.content.unwrap_or_default()).await {
        Ok(_) => ok_json(json!({"ok": true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn get_file_content(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or_default();
    let fm = state.files.lock().await.clone();
    match fm.safe_abs_path(&p).and_then(|abs| {
        let mut f = std::fs::File::open(abs)?;
        let mut buf = Vec::new();
        Read::by_ref(&mut f).take(2 * 1024 * 1024).read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }) {
        Ok(c) => ok_json(json!({"content": c})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn update_file_content(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    create_file(State(state), Json(req)).await
}

pub async fn get_permission(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let fm = state.files.lock().await.clone();
    let p = q.path.unwrap_or_default();
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    match fm.safe_abs_path(&p).and_then(|abs| Ok(std::fs::metadata(abs)?.permissions())) {
        Ok(perm) => {
            #[cfg(unix)]
            let m = perm.mode() & 0o777;
            #[cfg(not(unix))]
            let m = 0;
            ok_json(json!({"mode": m}))
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn set_permission(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let fm = state.files.lock().await.clone();
    let mode = req.mode.unwrap_or(0o644);
    match fm.safe_abs_path(&req.path).and_then(|abs| {
        #[cfg(unix)]
        std::fs::set_permissions(abs, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }) {
        Ok(_) => ok_json(json!({"ok": true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn set_visibility(State(state): State<AppState>, Json(req): Json<VisReq>) -> Response {
    if req.is_public {
        if let Err(e) = mark_public_recursive(&state, &req.path).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
    } else {
        delete_visibility_tree(&state.db, &req.path).await;
    }
    ok_json(json!({"ok": true}))
}

async fn mark_public_recursive(state: &AppState, rel: &str) -> anyhow::Result<()> {
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    for e in WalkDir::new(&abs).into_iter().filter_map(Result::ok) {
        let r = e.path().strip_prefix(&fm.root).unwrap();
        let rp = normalize_path(&format!("/{}", r.to_string_lossy()));
        upsert_visibility(&state.db, &rp, true).await?;
    }
    Ok(())
}

// ── Batch handlers ────────────────────────────────────────────────────────────

pub async fn batch_delete(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    let mut failed = Vec::new();
    for p in req.paths {
        if p.is_empty() || p == "/" { continue; }
        let fm = state.files.lock().await.clone();
        if fm.safe_abs_path(&p)
            .map(|abs| std::fs::remove_dir_all(&abs).or_else(|_| std::fs::remove_file(&abs)))
            .is_err()
        {
            failed.push(p.clone());
        }
        delete_visibility_tree(&state.db, &p).await;
    }
    if failed.is_empty() {
        ok_json(json!({"ok": true}))
    } else {
        (StatusCode::MULTI_STATUS, Json(json!({"ok": false, "failed": failed}))).into_response()
    }
}

pub async fn batch_move(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    batch_move_copy(state, req, true).await
}

pub async fn batch_copy(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    batch_move_copy(state, req, false).await
}

async fn batch_move_copy(state: AppState, req: BatchPaths, mv: bool) -> Response {
    let target = req.target.unwrap_or("/".into());
    let mut failed = Vec::new();
    let mut blocked = Vec::new();
    let tn = normalize_path(&target);
    for src in req.paths {
        let sn = normalize_path(&src);
        if sn == tn || format!("{tn}/").starts_with(&format!("{sn}/")) {
            blocked.push(src);
            continue;
        }
        let dst = format!(
            "{}/{}",
            tn.trim_end_matches('/'),
            Path::new(&sn).file_name().unwrap_or_default().to_string_lossy()
        );
        let resp = if mv {
            move_one(&state, &src, &dst).await
        } else {
            copy_one(&state, &src, &dst).await
        };
        if !resp.status().is_success() { failed.push(src); }
    }
    if !blocked.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "cannot move/copy a folder into itself or its subdirectory");
    }
    if failed.is_empty() {
        ok_json(json!({"ok": true}))
    } else {
        (StatusCode::MULTI_STATUS, Json(json!({"ok": false, "failed": failed}))).into_response()
    }
}

pub async fn batch_download(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    let fm = state.files.lock().await.clone();
    let fname = req.filename.unwrap_or("download".into());
    let fname = if fname.to_lowercase().ends_with(".zip") { fname } else { format!("{fname}.zip") };

    let entries: Vec<(PathBuf, String)> = req.paths.iter()
        .filter_map(|p| {
            fm.safe_abs_path(p).ok().map(|abs| {
                let name = Path::new(p).file_name().unwrap_or_default().to_string_lossy().to_string();
                (abs, name)
            })
        })
        .collect();

    if entries.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "no valid paths");
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<anyhow::Result<Vec<u8>>>();
    tokio::task::spawn_blocking(move || {
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut zw = ZipWriter::new(&mut buf);
        for (abs, name) in entries {
            let _ = zip_add_lstat(&mut zw, &abs, &name);
        }
        let _ = zw.finish();
        let _ = tx.send(Ok(buf.into_inner()));
    });

    match rx.await {
        Ok(Ok(data)) => download_bytes(data, "application/zip", &fname),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "zip failed"),
    }
}

// ── Public file handlers ──────────────────────────────────────────────────────

pub async fn list_public_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    if p == "/" {
        let rows = sqlx::query("SELECT file_path FROM file_visibilities WHERE is_public=1")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        let fm = state.files.lock().await.clone();
        let mut list = Vec::new();
        for r in rows {
            use sqlx::Row;
            let rel: String = r.get(0);
            let parent = Path::new(&rel).parent().unwrap_or(Path::new("/"));
            if parent != Path::new("/") && is_public(&state.db, &parent.to_string_lossy()).await {
                continue;
            }
            if let Ok(abs) = fm.safe_abs_path(&rel) {
                match file_info(&state.db, &abs, &rel).await {
                    Ok(fi) => list.push(fi),
                    Err(_) => {
                        let _ = sqlx::query("DELETE FROM file_visibilities WHERE file_path=?")
                            .bind(&rel)
                            .execute(&state.db)
                            .await;
                    }
                }
            }
        }
        ok_json(json!({"files": list, "path": p}))
    } else {
        match list_dir(&state, &p).await {
            Ok(v) => ok_json(json!({"files": v.into_iter().filter(|f| f.is_public).collect::<Vec<_>>(), "path": p})),
            Err(_) => ok_json(json!({"files": [], "path": p})),
        }
    }
}

pub async fn serve_public_file(State(state): State<AppState>, AxPath(path): AxPath<String>) -> Response {
    let rel = format!("/{path}");
    if !is_public(&state.db, &rel).await {
        return json_error(StatusCode::FORBIDDEN, "not public");
    }
    let fm = state.files.lock().await.clone();
    let abs = match fm.safe_abs_path(&rel) {
        Ok(a) => a,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if abs.is_dir() {
        match list_dir(&state, &rel).await {
            Ok(v) => ok_json(json!({"files": v.into_iter().filter(|f| f.is_public).collect::<Vec<_>>(), "path": rel})),
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    } else {
        serve_file_path(Ok(abs), false).await
    }
}

pub async fn download_public_file(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or_default();
    if !is_public(&state.db, &p).await {
        return json_error(StatusCode::FORBIDDEN, "not public");
    }
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&p), true).await
}

// ── Share handlers ────────────────────────────────────────────────────────────

pub async fn create_share(State(state): State<AppState>, req0: axum::extract::Request) -> Response {
    let user = req_user(&req0);
    let b = axum::body::to_bytes(req0.into_body(), usize::MAX).await.unwrap();
    let req: ShareReq = serde_json::from_slice(&b).unwrap();
    let code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let exp = req.expire_in.filter(|v| *v > 0)
        .map(|s| (Utc::now() + chrono::Duration::seconds(s)).to_rfc3339());
    let now = crate::util::now_string();
    match sqlx::query("INSERT INTO share_links (code,file_path,is_dir,user_id,expires_at,max_views,view_count,created_at) VALUES (?,?,?,?,?,?,0,?)")
        .bind(&code).bind(&req.path).bind(req.is_dir as i64).bind(user.id)
        .bind(&exp).bind(req.max_views.unwrap_or(0)).bind(now)
        .execute(&state.db).await
    {
        Ok(r) => {
            let link = get_share_by_id(&state.db, r.last_insert_rowid()).await.unwrap();
            Json(link).into_response()
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn list_shares(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let user = req_user(&req);
    let rows = sqlx::query("SELECT * FROM share_links WHERE user_id=?")
        .bind(user.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    Json(rows.into_iter().filter_map(|r| row_to_share(r).ok()).collect::<Vec<ShareLink>>()).into_response()
}

pub async fn delete_share(
    State(state): State<AppState>,
    AxPath(id): AxPath<i64>,
    req: axum::extract::Request,
) -> Response {
    let user = req_user(&req);
    let _ = sqlx::query("DELETE FROM share_links WHERE id=? AND user_id=?")
        .bind(id)
        .bind(user.id)
        .execute(&state.db)
        .await;
    ok_json(json!({"ok": true}))
}

pub async fn access_share(
    State(state): State<AppState>,
    AxPath(code): AxPath<String>,
    Query(q): Query<PathQuery>,
) -> Response {
    let link = match get_share(&state.db, &code, false).await {
        Ok(l) => l,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "not found"),
    };
    if link.is_dir {
        let sp = q.subpath.unwrap_or_default();
        let lp = if sp.is_empty() {
            link.file_path.clone()
        } else {
            format!("{}/{}", link.file_path, normalize_path(&sp).trim_start_matches('/'))
        };
        let list = list_dir(&state, &lp).await.unwrap_or_default();
        ok_json(json!({"files": list, "is_dir": true, "code": link.code, "file_path": link.file_path}))
    } else {
        ok_json(json!({"is_dir": false, "code": link.code, "file_path": link.file_path}))
    }
}

pub async fn download_share(
    State(state): State<AppState>,
    AxPath(code): AxPath<String>,
    Query(q): Query<PathQuery>,
) -> Response {
    let link = match get_share(&state.db, &code, true).await {
        Ok(l) => l,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "not found"),
    };
    let path = if link.is_dir {
        match q.subpath {
            Some(s) => format!("{}/{}", link.file_path, normalize_path(&s).trim_start_matches('/')),
            None => return json_error(StatusCode::BAD_REQUEST, "subpath required for directory share"),
        }
    } else {
        link.file_path
    };
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&path), true).await
}

pub async fn serve_share_raw(State(state): State<AppState>, AxPath(code): AxPath<String>) -> Response {
    let link = match get_share(&state.db, &code, true).await {
        Ok(l) => l,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "not found"),
    };
    if link.is_dir {
        return json_error(StatusCode::BAD_REQUEST, "cannot view directory as raw");
    }
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&link.file_path), false).await
}

// ── File serving ──────────────────────────────────────────────────────────────

fn ext_mime_override(ext: &str) -> Option<&'static str> {
    match ext {
        "md" | "markdown" | "yaml" | "yml" | "toml" | "ini" | "conf" | "env"
        | "log" | "sh" | "bash" | "zsh" | "fish" | "dockerfile"
        | "go" | "py" | "rs" | "rb" | "java" | "c" | "cpp" | "h"
        | "ts" | "tsx" | "jsx" | "vue" | "swift" | "kt" | "lua"
        | "r" | "sql" | "graphql" => Some("text/plain; charset=utf-8"),
        "avif" => Some("image/avif"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

fn is_browser_previewable(mime: &str) -> bool {
    if mime.starts_with("text/") || mime.starts_with("image/")
        || mime.starts_with("audio/") || mime.starts_with("video/")
    {
        return true;
    }
    matches!(
        mime,
        "application/pdf" | "application/json" | "application/javascript"
        | "application/x-javascript" | "application/xml" | "application/xhtml+xml"
        | "application/atom+xml" | "application/rss+xml" | "application/svg+xml"
    ) || mime.contains("xml") || mime.contains("javascript")
}

pub async fn serve_file_path(p: anyhow::Result<PathBuf>, attachment: bool) -> Response {
    let abs = match p {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if abs.is_dir() {
        return json_error(StatusCode::BAD_REQUEST, "cannot download a directory directly; use batch-download");
    }
    let file = match tokio::fs::File::open(&abs).await {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "not found"),
    };
    let meta = file.metadata().await.ok();
    let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let mime = ext_mime_override(&ext)
        .map(|s| s.to_string())
        .unwrap_or_else(|| mime_guess::from_path(&abs).first_or_octet_stream().to_string());
    let name = abs.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let base_mime = mime.split(';').next().unwrap_or("").trim();
    let disp = if attachment || !is_browser_previewable(base_mime) { "attachment" } else { "inline" };

    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);
    let mut resp = axum::response::Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    if let Some(m) = meta {
        resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(m.len()));
    }
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{disp}; filename=\"{name}\"")).unwrap(),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    resp
}

pub fn download_bytes(data: Vec<u8>, mime: &str, name: &str) -> Response {
    let mut resp = (StatusCode::OK, data).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")).unwrap(),
    );
    resp
}

// ── Misc file handlers ────────────────────────────────────────────────────────

pub async fn detect_file_type(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let fm = state.files.lock().await.clone();
    let p = q.path.unwrap_or_default();
    match fm.safe_abs_path(&p).and_then(|abs| {
        let mut f = std::fs::File::open(abs)?;
        let mut buf = [0u8; 512];
        let n = f.read(&mut buf)?;
        Ok(buf[..n].to_vec())
    }) {
        Ok(b) => {
            let text = !b.contains(&0);
            ok_json(json!({"text": text, "mime": if text { "text/plain; charset=utf-8" } else { "application/octet-stream" }}))
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, e),
    }
}

pub async fn search_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let Some(name) = q.name else {
        return json_error(StatusCode::BAD_REQUEST, "name is required");
    };
    let dir = q.dir.unwrap_or("/".into());
    let fm = state.files.lock().await.clone();
    let abs = match fm.safe_abs_path(&dir) {
        Ok(a) => a,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let root = fm.root();
    let kw = name.to_lowercase();
    let mut res = Vec::new();
    for e in WalkDir::new(abs).into_iter().filter_map(Result::ok).skip(1) {
        if res.len() >= 200 { break; }
        if e.file_name().to_string_lossy().to_lowercase().contains(&kw) {
            let rel = e.path().strip_prefix(&root).unwrap();
            res.push(json!({
                "name": e.file_name().to_string_lossy(),
                "path": normalize_path(&format!("/{}", rel.to_string_lossy())),
                "is_dir": e.file_type().is_dir(),
            }));
        }
    }
    ok_json(json!({"results": res}))
}

pub async fn list_dir_tree(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    match list_dir(&state, &p).await {
        Ok(v) => ok_json(json!({"dirs": v.into_iter().filter(|x| x.is_dir).map(|x| json!({"name": x.name, "path": x.path, "is_dir": true})).collect::<Vec<_>>(), "path": p})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn upload_folder(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
    mut mp: Multipart,
) -> Response {
    let dir = q.path.unwrap_or("/".into());
    let mut failed = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() != Some("files") { continue; }
        let rel = field.file_name().map(|s| s.to_string()).unwrap_or_default();
        let clean = normalize_path(&rel).trim_start_matches('/').to_string();
        match field.bytes().await {
            Ok(b) => {
                if write_rel(&state, &format!("{dir}/{clean}"), b).await.is_err() {
                    failed.push(clean);
                }
            }
            Err(_) => failed.push(clean),
        }
    }
    if failed.is_empty() {
        ok_json(json!({"ok": true}))
    } else {
        (StatusCode::MULTI_STATUS, Json(json!({"ok": true, "failed": failed}))).into_response()
    }
}

// ── Compress / Decompress ─────────────────────────────────────────────────────

pub async fn compress_files(State(state): State<AppState>, Json(mut req): Json<CompressReq>) -> Response {
    let fmt_str = req.format.take().unwrap_or("zip".into());
    let dir = req.dir.unwrap_or("/".into());
    let mut out = req.output.unwrap_or("archive".into());
    let fmt = match fmt_str.as_str() {
        "tar" => { if !out.ends_with(".tar") { out.push_str(".tar") } "tar" }
        "tar.gz" => { if !out.ends_with(".tar.gz") { out.push_str(".tar.gz") } "tar.gz" }
        _ => { if !out.ends_with(".zip") { out.push_str(".zip") } "zip" }
    };
    let fm = state.files.lock().await.clone();

    struct SrcEntry { abs: PathBuf, arc_name: String }
    let mut entries: Vec<SrcEntry> = Vec::new();
    for p in &req.paths {
        if let Ok(abs) = fm.safe_abs_path(p) {
            let arc_name = abs.file_name().unwrap_or_default().to_string_lossy().into_owned();
            entries.push(SrcEntry { abs, arc_name });
        }
    }
    if entries.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "no valid paths");
    }
    let out_abs = match fm.safe_abs_path(&format!("{dir}/{out}")) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if let Some(p) = out_abs.parent() { let _ = std::fs::create_dir_all(p); }

    let out_clone = out.clone();
    let join_result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let file = std::fs::File::create(&out_abs)?;
        match fmt {
            "zip" => {
                let mut zw = ZipWriter::new(file);
                for e in entries { zip_add_lstat(&mut zw, &e.abs, &e.arc_name)?; }
                zw.finish()?;
            }
            _ => {
                if fmt == "tar.gz" {
                    let enc = GzEncoder::new(file, Compression::default());
                    let mut tw = TarBuilder::new(enc);
                    tw.follow_symlinks(false);
                    for e in entries { tar_add(&mut tw, &e.abs, &e.arc_name)?; }
                    tw.into_inner()?.finish()?;
                } else {
                    let mut tw = TarBuilder::new(file);
                    tw.follow_symlinks(false);
                    for e in entries { tar_add(&mut tw, &e.abs, &e.arc_name)?; }
                    tw.finish()?;
                }
            }
        }
        Ok(())
    });
    let result = match join_result.await {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, anyhow!(e)),
    };
    match result {
        Ok(_) => ok_json(json!({"ok": true, "output": out_clone})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn decompress_file(State(state): State<AppState>, Json(req): Json<DecompressReq>) -> Response {
    let fm = state.files.lock().await.clone();
    let abs = match fm.safe_abs_path(&req.path) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let dest_rel = req.dir.unwrap_or_else(|| {
        Path::new(&req.path).parent()
            .map(|p| { let s = p.to_string_lossy(); if s.is_empty() || s == "." { "/".into() } else { s.into_owned() } })
            .unwrap_or_else(|| "/".into())
    });
    let dest = match fm.safe_abs_path(&dest_rel) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let name = abs.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

    fn safe_extract(dest: &Path, entry_name: &str, reader: &mut dyn Read, mode: u32, is_dir: bool) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let clean = dest.join(Path::new(&format!("/{}", entry_name)).components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect::<PathBuf>());
        if !clean.starts_with(dest) { return Ok(()); }
        if is_dir { return std::fs::create_dir_all(&clean); }
        if let Some(parent) = clean.parent() { std::fs::create_dir_all(parent)?; }
        let perm = std::fs::Permissions::from_mode((mode & 0o777) | 0o600);
        let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&clean)?;
        f.set_permissions(perm)?;
        std::io::copy(reader, &mut f)?;
        Ok(())
    }

    let result_join = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        std::fs::create_dir_all(&dest)?;
        if name.ends_with(".zip") {
            let f = std::fs::File::open(&abs)?;
            let mut za = ZipArchive::new(f)?;
            for i in 0..za.len() {
                let mut zf = za.by_index(i)?;
                let entry_name = zf.name().to_string();
                let is_dir = zf.is_dir();
                let mode = zf.unix_mode().unwrap_or(0o644);
                safe_extract(&dest, &entry_name, &mut zf, mode, is_dir)?;
            }
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            let f = std::fs::File::open(&abs)?;
            let mut tr = TarArchive::new(GzDecoder::new(f));
            for entry in tr.entries()? {
                let mut entry = entry?;
                let hdr = entry.header().clone();
                let entry_path = hdr.path()?.to_string_lossy().into_owned();
                let is_dir = hdr.entry_type().is_dir();
                let mode = hdr.mode().unwrap_or(0o644);
                safe_extract(&dest, &entry_path, &mut entry, mode, is_dir)?;
            }
        } else if name.ends_with(".tar") {
            let f = std::fs::File::open(&abs)?;
            let mut tr = TarArchive::new(f);
            for entry in tr.entries()? {
                let mut entry = entry?;
                let hdr = entry.header().clone();
                let entry_path = hdr.path()?.to_string_lossy().into_owned();
                let is_dir = hdr.entry_type().is_dir();
                let mode = hdr.mode().unwrap_or(0o644);
                safe_extract(&dest, &entry_path, &mut entry, mode, is_dir)?;
            }
        } else if name.ends_with(".gz") {
            let f = std::fs::File::open(&abs)?;
            let mut gz = GzDecoder::new(f);
            let out_name = abs.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            safe_extract(&dest, &out_name, &mut gz, 0o644, false)?;
        } else {
            return Err(anyhow!("unsupported archive format"));
        }
        Ok(())
    });
    let result: anyhow::Result<()> = match result_join.await {
        Ok(r) => r.map_err(|e| anyhow!(e)),
        Err(e) => Err(anyhow!(e)),
    };
    match result {
        Ok(_) => ok_json(json!({"ok": true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// ── URL fetch ─────────────────────────────────────────────────────────────────

const GITHUB_PROXY_PREFIXES: &[&str] = &[
    "https://gh-proxy.com/",
    "https://gh.ddlc.top/",
    "https://ghproxy.it/",
];

fn is_github_url(raw: &str) -> bool {
    let github_hosts = [
        "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
        "codeload.github.com", "releases.githubusercontent.com",
        "gist.githubusercontent.com", "gist.github.com",
    ];
    if let Ok(u) = url::Url::parse(raw) {
        if let Some(host) = u.host_str() {
            let h = host.to_lowercase();
            for gh in &github_hosts {
                if h == *gh || h.ends_with(&format!(".{}", gh)) { return true; }
            }
        }
    }
    false
}

async fn validate_public_url(raw: &str) -> anyhow::Result<()> {
    let u = url::Url::parse(raw)?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(anyhow!("only http/https URLs are allowed"));
    }
    let host = u.host_str().ok_or_else(|| anyhow!("missing host"))?;
    if host.eq_ignore_ascii_case("localhost") {
        return Err(anyhow!("requests to private/internal addresses are not allowed"));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(ip) {
            return Err(anyhow!("requests to private/internal addresses are not allowed"));
        }
    }
    Ok(())
}

pub async fn fetch_url(State(state): State<AppState>, Json(req): Json<FetchReq>) -> Response {
    if let Err(e) = validate_public_url(&req.url).await {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    let fm = state.files.lock().await.clone();
    let dir = match fm.safe_abs_path(&req.dir.clone().unwrap_or("/".into())) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let _ = fs::create_dir_all(&dir).await;

    let fname = req.filename.clone().unwrap_or_else(|| {
        url::Url::parse(&req.url).ok()
            .and_then(|u| u.path_segments()?.last().map(str::to_string))
            .filter(|s| !s.is_empty() && *s != "." && *s != "/")
            .unwrap_or("download".into())
    });
    let out = dir.join(safe_name(&fname));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1800))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .unwrap();

    let mut urls_to_try: Vec<String> = vec![req.url.clone()];
    if is_github_url(&req.url) {
        for prefix in GITHUB_PROXY_PREFIXES {
            urls_to_try.push(format!("{}{}", prefix, req.url));
        }
    }

    let mut last_err = String::new();
    for try_url in &urls_to_try {
        match client.get(try_url).send().await {
            Ok(r) if r.status().is_success() => {
                match tokio::fs::File::create(&out).await {
                    Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
                    Ok(mut file) => {
                        let mut stream = r.bytes_stream();
                        let mut ok = true;
                        while let Some(chunk) = stream.next().await {
                            match chunk {
                                Ok(bytes) => {
                                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await {
                                        last_err = e.to_string();
                                        ok = false;
                                        break;
                                    }
                                }
                                Err(e) => { last_err = e.to_string(); ok = false; break; }
                            }
                        }
                        if ok { return ok_json(json!({"ok": true})); }
                        let _ = tokio::fs::remove_file(&out).await;
                    }
                }
            }
            Ok(r) => { last_err = format!("remote returned {} [{}]", r.status(), try_url); }
            Err(e) => { last_err = format!("fetch failed [{}]: {}", try_url, e); }
        }
    }
    json_error(StatusCode::INTERNAL_SERVER_ERROR, last_err)
}

// ── Archive helpers ───────────────────────────────────────────────────────────

pub fn zip_add_lstat<W: Write + std::io::Seek>(
    zw: &mut ZipWriter<W>,
    abs: &Path,
    name: &str,
) -> zip::result::ZipResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let info = match abs.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if info.is_dir() {
        for e in std::fs::read_dir(abs)? {
            let e = e?;
            zip_add_lstat(zw, &e.path(), &format!("{}/{}", name, e.file_name().to_string_lossy()))?;
        }
    } else if info.is_file() {
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(info.permissions().mode());
        zw.start_file(name, opts)?;
        let mut f = std::fs::File::open(abs)?;
        std::io::copy(&mut f, zw)?;
    }
    Ok(())
}

fn tar_add<W: Write>(tw: &mut TarBuilder<W>, abs: &Path, name: &str) -> std::io::Result<()> {
    let info = abs.symlink_metadata()?;
    if info.is_dir() {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_metadata(&info);
        hdr.set_path(format!("{}/", name))?;
        hdr.set_cksum();
        tw.append(&hdr, std::io::empty())?;
        for e in std::fs::read_dir(abs)? {
            let e = e?;
            tar_add(tw, &e.path(), &format!("{}/{}", name, e.file_name().to_string_lossy()))?;
        }
    } else if info.is_file() {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_metadata(&info);
        hdr.set_path(name)?;
        hdr.set_cksum();
        let mut f = std::fs::File::open(abs)?;
        tw.append(&hdr, &mut f)?;
    }
    Ok(())
}
