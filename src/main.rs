use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    http::{Method, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, delete, get, post, put},
};
use clap::Parser;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{fs, net::TcpListener};
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod config;
mod db;
mod handler;
mod terminal;
mod types;
mod util;
mod webdav;

mod embedded_frontend {
    include!(concat!(env!("OUT_DIR"), "/embedded_frontend.rs"));
}

use auth::{
    auth_middleware, auth_status, get_user, login, setup, update_user,
};
use config::{ensure_conf, load_conf};
use db::{get_settings, init_db, update_setting_storage};
use handler::{
    batch_copy, batch_delete, batch_download, batch_move, compress_files,
    create_file, decompress_file, delete_file, detect_file_type, download_file,
    download_public_file, fetch_url, get_file_content, get_permission,
    get_settings_api, list_dir_tree, list_files, list_public_files, mkdir,
    move_file, copy_file, search_files, serve_public_file, set_permission,
    set_visibility, update_file_content, update_settings, upload_file,
    upload_folder,
};
use handler::{access_share, create_share, delete_share, download_share, list_shares, serve_share_raw};
use types::{AppState, FileManager, RateLimiter};
use util::decrypt_opt;
use webdav::webdav_handler;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    dir: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct WebdavReq {
    webdav_enabled: bool,
    webdav_sub_path: Option<String>,
    webdav_username: Option<String>,
    webdav_password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let (data_dir, mut storage_dir) = match (&args.config, &args.dir) {
        (Some(c), Some(d)) => (c.clone(), d.clone()),
        (Some(c), None) => (c.clone(), c.join("storage")),
        (None, Some(d)) => (PathBuf::from("./data"), d.clone()),
        (None, None) => (PathBuf::from("./data"), PathBuf::from("./data/storage")),
    };
    fs::create_dir_all(&data_dir).await?;
    fs::create_dir_all(&storage_dir).await?;
    ensure_conf(&data_dir).await?;

    let master_key_text = match std::env::var("CLOUDONE_MASTER_KEY") {
        Ok(v) => v,
        Err(_) => {
            let p = data_dir.join("master.key");
            match fs::read_to_string(&p).await {
                Ok(v) => v,
                Err(_) => {
                    let mut b = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut b);
                    let v = hex::encode(b);
                    fs::write(&p, &v).await?;
                    v
                }
            }
        }
    };
    let master_key: [u8; 32] = Sha256::digest(master_key_text.as_bytes()).into();

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}?mode=rwc", data_dir.join("cloudone.db").display()))
        .await?;
    init_db(&db).await?;

    let mut settings = get_settings(&db).await?;
    if let Some(dir) = args.dir {
        storage_dir = dir;
        update_setting_storage(&db, &storage_dir.to_string_lossy()).await?;
    } else if !settings.storage_dir.is_empty() {
        storage_dir = PathBuf::from(&settings.storage_dir);
    }
    fs::create_dir_all(&storage_dir).await?;
    settings = get_settings(&db).await?;

    let jwt_secret = match std::env::var("CLOUDONE_JWT_SECRET") {
        Ok(v) => v,
        Err(_) => decrypt_opt(&master_key, &settings.jwt_secret_enc).unwrap_or_default(),
    };
    let jwt_secret = if jwt_secret.is_empty() {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let s = hex::encode(b);
        let enc = util::encrypt(&master_key, &s)?;
        sqlx::query("UPDATE settings SET jwt_secret_enc=? WHERE id=1")
            .bind(enc)
            .execute(&db)
            .await?;
        s
    } else {
        jwt_secret
    };

    let state = AppState {
        db,
        files: Arc::new(tokio::sync::Mutex::new(FileManager::new(storage_dir))),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        master_key: Arc::new(master_key),
        login_limiter: Arc::new(RateLimiter::new(5, Duration::from_secs(60))),
        webdav_limiter: Arc::new(RateLimiter::new(10, Duration::from_secs(60))),
    };
    state.login_limiter.spawn_cleanup();
    state.webdav_limiter.spawn_cleanup();

    let app = build_router(state);
    let cfg = load_conf(&data_dir).await?;
    let addr = format!("{}:{}", cfg.0, cfg.1);
    eprintln!("CloudOne Rust backend starting on {addr}");
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS, Method::HEAD,
            Method::from_bytes(b"PROPFIND").unwrap(),
            Method::from_bytes(b"PROPPATCH").unwrap(),
            Method::from_bytes(b"MKCOL").unwrap(),
            Method::from_bytes(b"COPY").unwrap(),
            Method::from_bytes(b"MOVE").unwrap(),
            Method::from_bytes(b"LOCK").unwrap(),
            Method::from_bytes(b"UNLOCK").unwrap(),
        ])
        .allow_headers(Any)
        .expose_headers([
            header::CONTENT_DISPOSITION,
            header::HeaderName::from_static("dav"),
            header::HeaderName::from_static("lock-token"),
        ]);

    let authed = Router::new()
        .route("/user", get(get_user).put(update_user))
        .route("/settings", get(get_settings_api).put(update_settings))
        .route("/files", get(list_files).delete(delete_file))
        .route("/files/upload", post(upload_file))
        .route("/files/mkdir", post(mkdir))
        .route("/files/move", post(move_file))
        .route("/files/copy", post(copy_file))
        .route("/files/download", get(download_file))
        .route("/files/create", post(create_file))
        .route("/files/content", get(get_file_content).put(update_file_content))
        .route("/files/detect", get(detect_file_type))
        .route("/files/visibility", put(set_visibility))
        .route("/files/permission", get(get_permission).put(set_permission))
        .route("/files/batch-delete", post(batch_delete))
        .route("/files/batch-download", post(batch_download))
        .route("/files/batch-move", post(batch_move))
        .route("/files/batch-copy", post(batch_copy))
        .route("/files/compress", post(compress_files))
        .route("/files/decompress", post(decompress_file))
        .route("/files/fetch-url", post(fetch_url))
        .route("/files/search", get(search_files))
        .route("/files/upload-folder", post(upload_folder))
        .route("/files/dirtree", get(list_dir_tree))
        .route("/ws/terminal", get(terminal::terminal_ws))
        .route("/share", get(list_shares).post(create_share))
        .route("/share/{id}", delete(delete_share))
        .route("/webdav/settings", get(get_webdav_settings).put(update_webdav_settings))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let api = Router::new()
        .route("/auth/status", get(auth_status))
        .route("/auth/setup", post(setup))
        .route("/auth/login", post(login))
        .route("/s/{code}", get(access_share))
        .route("/s/{code}/download", get(download_share))
        .merge(authed);

    Router::new()
        .nest("/api", api)
        .route("/public", get(list_public_files))
        .route("/pub/list", get(list_public_files))
        .route("/pub/dl", get(download_public_file))
        .route("/raw/{*path}", get(serve_public_file))
        .route("/s/{code}/raw", get(serve_share_raw))
        .route("/dav", any(webdav_handler))
        .route("/dav/{*path}", any(webdav_handler))
        .fallback(static_fallback)
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
        .with_state(state)
}

// ── WebDAV settings handlers (kept in main to avoid circular deps) ────────────

async fn get_webdav_settings(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
    let s = get_settings(&state.db).await.unwrap();
    util::ok_json(serde_json::json!({
        "webdav_enabled": s.webdav_enabled,
        "webdav_sub_path": s.webdav_sub_path,
        "webdav_username": s.webdav_username,
        "webdav_has_password": !s.webdav_password_enc.is_empty(),
    }))
}

async fn update_webdav_settings(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<WebdavReq>,
) -> Response {
    let mut enc = None;
    if let Some(p) = req.webdav_password.filter(|s| !s.is_empty()) {
        let h = bcrypt::hash(p, bcrypt::DEFAULT_COST).unwrap();
        enc = Some(util::encrypt(&state.master_key, &h).unwrap());
    }
    let mut q = "UPDATE settings SET webdav_enabled=?,webdav_sub_path=?,webdav_username=?".to_string();
    if enc.is_some() { q.push_str(",webdav_password_enc=?"); }
    q.push_str(" WHERE id=1");
    let mut query = sqlx::query(&q)
        .bind(req.webdav_enabled as i64)
        .bind(req.webdav_sub_path.unwrap_or_default())
        .bind(req.webdav_username.unwrap_or_default());
    if let Some(e) = enc { query = query.bind(e); }
    let _ = query.execute(&state.db).await;
    get_webdav_settings(axum::extract::State(state)).await
}

// ── Static frontend ───────────────────────────────────────────────────────────

async fn static_fallback(req: Request<Body>) -> Response {
    let mut path = req.uri().path().trim_start_matches('/').to_string();
    if path.is_empty() { path = "index.html".into(); }

    if let Some((data, mime)) = embedded_frontend::get(&path).or_else(|| embedded_frontend::get("index.html")) {
        return embedded_frontend_response(data, mime);
    }

    let candidate = PathBuf::from("frontend/dist").join(&path);
    let p = if candidate.exists() { candidate } else { PathBuf::from("frontend/dist/index.html") };
    if p.exists() {
        handler::serve_file_path(Ok(p), false).await
    } else {
        (StatusCode::OK, "CloudOne frontend is not built. Run `cd frontend && npm run build` before compiling the Rust binary.").into_response()
    }
}

fn embedded_frontend_response(data: &'static [u8], mime: &'static str) -> Response {
    use axum::http::HeaderValue;
    let mut resp = Response::new(Body::from(axum::body::Bytes::from_static(data)));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp
}
