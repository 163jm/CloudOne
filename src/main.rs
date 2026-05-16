use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{Read, Write},
    net::IpAddr,
    os::unix::io::{FromRawFd, RawFd},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Multipart, Path as AxPath, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{DateTime, Utc};
use clap::Parser;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{Rng, RngCore, distributions::Alphanumeric};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use tar::{Archive as TarArchive, Builder as TarBuilder};
use std::os::unix::process::CommandExt;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    sync::Mutex,
};
use tower_http::cors::{Any, CorsLayer};
use walkdir::WalkDir;
mod embedded_frontend {
    include!(concat!(env!("OUT_DIR"), "/embedded_frontend.rs"));
}
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    dir: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    files: Arc<Mutex<FileManager>>,
    jwt_secret: Arc<Vec<u8>>,
    master_key: Arc<[u8; 32]>,
    login_limiter: Arc<RateLimiter>,
    webdav_limiter: Arc<RateLimiter>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    id: i64,
    username: String,
    #[serde(skip_serializing)]
    password: String,
    #[serde(skip_serializing)]
    token_version: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Clone)]
struct Settings {
    id: i64,
    storage_dir: String,
    lang: String,
    ui_theme: String,
    ui_font: String,
    editor_font: String,
    webdav_enabled: bool,
    webdav_sub_path: String,
    webdav_username: String,
    #[serde(skip_serializing)]
    webdav_password_enc: String,
    #[serde(skip_serializing)]
    jwt_secret_enc: String,
    show_hidden: bool,
}

#[derive(Debug, Serialize, Clone)]
struct ShareLink {
    id: i64,
    code: String,
    file_path: String,
    is_dir: bool,
    user_id: i64,
    expires_at: Option<String>,
    max_views: i64,
    view_count: i64,
    created_at: String,
}

#[derive(Debug, Serialize, Clone)]
struct FileInfo {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    mod_time: String,
    is_public: bool,
    mode: u32,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    name: String,
    path: String,
    is_dir: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: i64,
    version: i64,
    exp: usize,
    iat: usize,
}

#[derive(Clone)]
struct FileManager {
    root: PathBuf,
}

#[derive(Default)]
struct RateLimiter {
    max: usize,
    window: Duration,
    hits: Mutex<HashMap<String, Vec<SystemTime>>>,
}

impl RateLimiter {
    fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }
    async fn allow(&self, ip: String) -> bool {
        let now = SystemTime::now();
        let cutoff = now - self.window;
        let mut guard = self.hits.lock().await;
        let entry = guard.entry(ip).or_default();
        entry.retain(|t| *t > cutoff);
        if entry.len() >= self.max {
            return false;
        }
        entry.push(now);
        true
    }
}

fn now_string() -> String {
    Utc::now().to_rfc3339()
}
fn unix_now() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize
}
fn normalize_path(p: &str) -> String {
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
fn is_danger_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    ["/proc", "/sys", "/dev"]
        .iter()
        .any(|x| s == *x || s.starts_with(&format!("{x}/")))
}
fn safe_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .unwrap_or_else(|| OsStr::new("download"))
        .to_string_lossy()
        .to_string()
}

impl FileManager {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
    fn set_root(&mut self, root: PathBuf) {
        self.root = root;
    }
    fn root(&self) -> PathBuf {
        self.root.clone()
    }
    fn abs_path(&self, rel: &str) -> Result<PathBuf> {
        let norm = normalize_path(rel);
        let sub = norm.trim_start_matches('/');
        let abs = self.root.join(sub);
        let root = self.root.clone();
        if root != PathBuf::from("/") && !abs.starts_with(&root) {
            return Err(anyhow!("invalid path: path traversal detected"));
        }
        Ok(abs)
    }
    fn safe_abs_path(&self, rel: &str) -> Result<PathBuf> {
        let abs = self.abs_path(rel)?;
        if is_danger_path(&abs) {
            return Err(anyhow!("access denied: virtual filesystem path"));
        }
        Ok(abs)
    }
}

fn json_error(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({"error": msg.to_string()}))).into_response()
}
fn ok_json(v: Value) -> Response {
    Json(v).into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    // jsonwebtoken 10.x 依赖 rustls CryptoProvider，必须在第一次使用 JWT 前初始化
    // 忽略返回值：若已被其他 crate（如 reqwest）安装过则直接跳过
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
        .connect(&format!(
            "sqlite://{}?mode=rwc",
            data_dir.join("cloudone.db").display()
        ))
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
        let enc = encrypt(&master_key, &s)?;
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
        files: Arc::new(Mutex::new(FileManager::new(storage_dir))),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        master_key: Arc::new(master_key),
        login_limiter: Arc::new(RateLimiter::new(5, Duration::from_secs(60))),
        webdav_limiter: Arc::new(RateLimiter::new(10, Duration::from_secs(60))),
    };
    let app = build_router(state);
    let cfg = load_conf(&data_dir).await?;
    let addr = format!("{}:{}", cfg.0, cfg.1);
    eprintln!("CloudOne Rust backend starting on {addr}");
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
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
        .route(
            "/files/content",
            get(get_file_content).put(update_file_content),
        )
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
        .route("/ws/terminal", get(terminal_ws))
        .route("/share", get(list_shares).post(create_share))
        .route("/share/{id}", delete(delete_share))
        .route(
            "/webdav/settings",
            get(get_webdav_settings).put(update_webdav_settings),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));
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

async fn init_db(db: &SqlitePool) -> Result<()> {
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
async fn get_settings(db: &SqlitePool) -> Result<Settings> {
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
async fn update_setting_storage(db: &SqlitePool, s: &str) -> Result<()> {
    sqlx::query("UPDATE settings SET storage_dir=? WHERE id=1")
        .bind(s)
        .execute(db)
        .await?;
    Ok(())
}

async fn get_user_by_id(db: &SqlitePool, id: i64) -> Result<User> {
    row_to_user(
        sqlx::query("SELECT * FROM users WHERE id=?")
            .bind(id)
            .fetch_one(db)
            .await?,
    )
}
fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: r.get("id"),
        username: r.get("username"),
        password: r.get("password"),
        token_version: r.try_get("token_version").unwrap_or(0),
        created_at: r.try_get("created_at").unwrap_or_default(),
        updated_at: r.try_get("updated_at").unwrap_or_default(),
    })
}
fn gen_token(state: &AppState, user: &User) -> Result<String> {
    let now = unix_now();
    let claims = Claims {
        sub: user.id,
        version: user.token_version,
        iat: now,
        exp: now + 7 * 24 * 3600,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&state.jwt_secret),
    )?)
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(str::to_string))
        .or_else(|| {
            req.uri().query().and_then(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "token")
                    .map(|(_, v)| v.into_owned())
            })
        });
    let Some(token) = token else {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(&state.jwt_secret),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let user = match get_user_by_id(&state.db, data.claims.sub).await {
        Ok(u) => u,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "user not found"),
    };
    if user.token_version != data.claims.version {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "token has been revoked, please login again",
        );
    }
    req.extensions_mut().insert(user);
    next.run(req).await
}
fn req_user(req: &Request<Body>) -> User {
    req.extensions().get::<User>().unwrap().clone()
}

async fn auth_status(State(state): State<AppState>) -> Response {
    let c: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    ok_json(json!({"setup": c>0}))
}
#[derive(Deserialize)]
struct AuthReq {
    username: String,
    password: String,
}
async fn setup(State(state): State<AppState>, Json(req): Json<AuthReq>) -> Response {
    let c: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if c > 0 {
        return json_error(StatusCode::BAD_REQUEST, "already setup");
    }
    // 用 spawn_blocking 避免 bcrypt 阻塞 tokio 异步线程（cost=12 约需 300ms CPU）
    let password = req.password.clone();
    let h = match tokio::task::spawn_blocking(move || hash(password, DEFAULT_COST)).await {
        Ok(Ok(v)) => v,
        Ok(Err(_)) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to hash password"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    // 再次检查，防止并发双重提交（bcrypt 耗时期间可能有第二个请求到达）
    let c2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if c2 > 0 {
        return json_error(StatusCode::BAD_REQUEST, "already setup");
    }
    let now = now_string();
    let id = match sqlx::query("INSERT INTO users (username,password,token_version,created_at,updated_at) VALUES (?,?,?,?,?)")
        .bind(&req.username).bind(h).bind(0i64).bind(&now).bind(&now)
        .execute(&state.db).await
    {
        Ok(r) => r.last_insert_rowid(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let user = get_user_by_id(&state.db, id).await.unwrap();
    let token = gen_token(&state, &user).unwrap();
    ok_json(json!({"token":token,"user":user}))
}
async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<AuthReq>,
) -> Response {
    if !state.login_limiter.allow(real_ip(&headers, addr)).await {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts, please try again later",
        );
    }
    let row = sqlx::query("SELECT * FROM users WHERE username=?")
        .bind(req.username)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(row) = row else {
        return json_error(StatusCode::UNAUTHORIZED, "invalid credentials");
    };
    let user = row_to_user(row).unwrap();
    let password = req.password.clone();
    let stored_hash = user.password.clone();
    let valid = tokio::task::spawn_blocking(move || verify(password, &stored_hash))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(false);
    if !valid {
        return json_error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    let token = gen_token(&state, &user).unwrap();
    ok_json(json!({"token":token,"user":user}))
}
async fn get_user(req: Request<Body>) -> Response {
    ok_json(json!(req_user(&req)))
}
#[derive(Deserialize)]
struct UpdateUserReq {
    username: Option<String>,
    password: Option<String>,
}
async fn update_user(State(state): State<AppState>, req0: Request<Body>) -> Response {
    let user = req_user(&req0);
    let bytes = axum::body::to_bytes(req0.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let req: UpdateUserReq = serde_json::from_slice(&bytes).unwrap_or(UpdateUserReq {
        username: None,
        password: None,
    });
    let mut version = user.token_version;
    let mut password = user.password.clone();
    let mut username = user.username.clone();
    if let Some(u) = req.username.filter(|s| !s.is_empty()) {
        username = u;
    }
    let password_changed = if let Some(p) = req.password.filter(|s| !s.is_empty()) {
        password = tokio::task::spawn_blocking(move || hash(p, DEFAULT_COST))
            .await
            .unwrap()
            .unwrap();
        version += 1;
        true
    } else {
        false
    };
    let now = now_string();
    if let Err(e) = sqlx::query(
        "UPDATE users SET username=?,password=?,token_version=?,updated_at=? WHERE id=?",
    )
    .bind(&username)
    .bind(&password)
    .bind(version)
    .bind(&now)
    .bind(user.id)
    .execute(&state.db)
    .await
    {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    let user = get_user_by_id(&state.db, user.id).await.unwrap();
    let mut resp = json!({"user":user});
    if password_changed {
        resp["token"] = json!(gen_token(&state, &user).unwrap());
    }
    ok_json(resp)
}

async fn get_settings_api(State(state): State<AppState>) -> Response {
    match get_settings(&state.db).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
#[derive(Deserialize)]
struct SettingsReq {
    storage_dir: Option<String>,
    lang: Option<String>,
    ui_theme: Option<String>,
    ui_font: Option<String>,
    editor_font: Option<String>,
    show_hidden: Option<bool>,
}
async fn update_settings(State(state): State<AppState>, Json(req): Json<SettingsReq>) -> Response {
    let mut s = get_settings(&state.db).await.unwrap();
    if let Some(d) = req.storage_dir.filter(|v| !v.is_empty()) {
        let clean = PathBuf::from(&d);
        let forbidden = [
            "/etc",
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/boot",
            "/sys",
            "/proc",
            "/dev",
            "/run",
            "/var/run",
        ];
        let cs = clean.to_string_lossy();
        if forbidden
            .iter()
            .any(|f| cs == *f || cs.starts_with(&format!("{f}/")))
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "storage_dir points to a system directory",
            );
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
    if let Some(v) = req.lang.filter(|v| !v.is_empty()) {
        s.lang = v
    }
    if let Some(v) = req.ui_theme.filter(|v| !v.is_empty()) {
        s.ui_theme = v
    }
    if let Some(v) = req.ui_font.filter(|v| !v.is_empty()) {
        s.ui_font = v
    }
    if let Some(v) = req.editor_font.filter(|v| !v.is_empty()) {
        s.editor_font = v
    }
    if let Some(v) = req.show_hidden {
        s.show_hidden = v
    }
    sqlx::query("UPDATE settings SET storage_dir=?,lang=?,ui_theme=?,ui_font=?,editor_font=?,show_hidden=? WHERE id=?").bind(&s.storage_dir).bind(&s.lang).bind(&s.ui_theme).bind(&s.ui_font).bind(&s.editor_font).bind(s.show_hidden as i64).bind(s.id).execute(&state.db).await.unwrap();
    Json(s).into_response()
}

async fn is_public(db: &SqlitePool, rel: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM file_visibilities WHERE file_path=? AND is_public=1",
    )
    .bind(normalize_path(rel))
    .fetch_one(db)
    .await
    .unwrap_or(0)
        > 0
}
async fn upsert_visibility(db: &SqlitePool, rel: &str, public: bool) -> Result<()> {
    sqlx::query("INSERT INTO file_visibilities (file_path,is_public) VALUES (?,?) ON CONFLICT(file_path) DO UPDATE SET is_public=excluded.is_public").bind(normalize_path(rel)).bind(public as i64).execute(db).await?;
    Ok(())
}
async fn file_info(db: &SqlitePool, abs: &Path, rel: &str) -> Result<FileInfo> {
    let md = fs::metadata(abs).await?;
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
async fn list_dir(state: &AppState, rel: &str) -> Result<Vec<FileInfo>> {
    let settings = get_settings(&state.db).await?;
    let show_hidden = settings.show_hidden;
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    let mut rd = fs::read_dir(&abs).await?;
    let base = normalize_path(rel);

    // 先收集所有条目，批量查询可见性（避免 N+1 问题）
    let mut entries: Vec<(PathBuf, String)> = Vec::new();
    while let Some(e) = rd.next_entry().await? {
        let p = e.path();
        if is_danger_path(&p) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        // 过滤隐藏文件（以 . 开头）
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let child = normalize_path(&format!("{}/{}", base, name));
        entries.push((p, child));
    }

    // 批量查询可见性
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
        // 用 tokio spawn_blocking 读取元数据，跟随符号链接
        let meta = tokio::task::spawn_blocking(move || std::fs::metadata(&abs_p)).await;
        if let Ok(Ok(md)) = meta {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(unix)]
            let mode = md.permissions().mode();
            #[cfg(not(unix))]
            let mode = 0u32;

            let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let fi = FileInfo {
                name,
                path: child.clone(),
                is_dir: md.is_dir(),
                size: if md.is_dir() { 0 } else { md.len() },
                mod_time: DateTime::<Utc>::from(md.modified().unwrap_or(SystemTime::now())).to_rfc3339(),
                is_public: *vis_map.get(&child).unwrap_or(&false),
                mode,
            };
            out.push(fi);
        }
    }
    Ok(out)
}
#[derive(Deserialize)]
struct PathQuery {
    path: Option<String>,
    name: Option<String>,
    dir: Option<String>,
    subpath: Option<String>,
}
async fn list_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    match list_dir(&state, &p).await {
        Ok(v) => ok_json(json!({"files":v,"path":p})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn delete_file(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let Some(p) = q.path else {
        return json_error(StatusCode::BAD_REQUEST, "path is required");
    };
    if p == "/" || p.is_empty() {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot delete root directory",
        );
    };
    let fm = state.files.lock().await.clone();
    match fm.safe_abs_path(&p).and_then(|abs| {
        std::fs::remove_dir_all(&abs)
            .or_else(|_| std::fs::remove_file(&abs))
            .map_err(Into::into)
    }) {
        Ok(_) => {
            delete_visibility_tree(&state.db, &p).await;
            ok_json(json!({"ok":true}))
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn write_rel(state: &AppState, rel: &str, data: impl AsRef<[u8]>) -> Result<()> {
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    if let Some(p) = abs.parent() {
        fs::create_dir_all(p).await?;
    }
    fs::write(abs, data).await?;
    Ok(())
}
async fn upload_file(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
    mut mp: Multipart,
) -> Response {
    let dir = q.path.unwrap_or("/".into());
    let mut failed = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() != Some("files") {
            continue;
        }
        let name = field.file_name().map(|s| s.to_string()).unwrap_or_default();
        let safe = safe_name(&name);
        match field.bytes().await {
            Ok(b) => {
                if write_rel(&state, &format!("{dir}/{safe}"), b)
                    .await
                    .is_err()
                {
                    failed.push(name)
                }
            }
            Err(_) => failed.push(name),
        }
    }
    if failed.is_empty() {
        ok_json(json!({"ok":true}))
    } else {
        (
            StatusCode::MULTI_STATUS,
            Json(json!({"ok":true,"failed":failed})),
        )
            .into_response()
    }
}
#[derive(Deserialize)]
struct OnePath {
    path: String,
    content: Option<String>,
    mode: Option<u32>,
}
async fn mkdir(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    let fm = state.files.lock().await.clone();
    match fm
        .safe_abs_path(&req.path)
        .and_then(|p| std::fs::create_dir_all(p).map_err(Into::into))
    {
        Ok(_) => ok_json(json!({"ok":true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
#[derive(Deserialize)]
struct MoveReq {
    src: String,
    dst: String,
}
async fn move_file(State(state): State<AppState>, Json(req): Json<MoveReq>) -> Response {
    move_one(&state, &req.src, &req.dst).await
}
async fn copy_file(State(state): State<AppState>, Json(req): Json<MoveReq>) -> Response {
    copy_one(&state, &req.src, &req.dst).await
}
async fn move_one(state: &AppState, src: &str, dst: &str) -> Response {
    let fm = state.files.lock().await.clone();
    match (fm.safe_abs_path(src), fm.safe_abs_path(dst)) {
        (Ok(s), Ok(d)) => match std::fs::rename(&s, &d) {
            Ok(_) => {
                migrate_visibility(&state.db, src, dst).await;
                ok_json(json!({"ok":true}))
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
                ok_json(json!({"ok":true}))
            }
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        (Err(e), _) | (_, Err(e)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
fn copy_path(src: &Path, dst: &Path) -> std::io::Result<()> {
    let md = std::fs::metadata(src)?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            copy_path(&e.path(), &dst.join(e.file_name()))?
        }
    } else {
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}
async fn download_file(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or_default();
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&p), true).await
}
async fn create_file(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    match write_rel(&state, &req.path, req.content.unwrap_or_default()).await {
        Ok(_) => ok_json(json!({"ok":true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn get_file_content(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or_default();
    let fm = state.files.lock().await.clone();
    match fm.safe_abs_path(&p).and_then(|abs| {
        let mut f = std::fs::File::open(abs)?;
        let mut buf = Vec::new();
        std::io::Read::by_ref(&mut f)
            .take(2 * 1024 * 1024)
            .read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }) {
        Ok(c) => ok_json(json!({"content":c})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn update_file_content(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    create_file(State(state), Json(req)).await
}
async fn get_permission(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let fm = state.files.lock().await.clone();
    let p = q.path.unwrap_or_default();
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    match fm
        .safe_abs_path(&p)
        .and_then(|abs| Ok(std::fs::metadata(abs)?.permissions()))
    {
        Ok(perm) => {
            #[cfg(unix)]
            let m = perm.mode() & 0o777;
            #[cfg(not(unix))]
            let m = 0;
            ok_json(json!({"mode":m}))
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn set_permission(State(state): State<AppState>, Json(req): Json<OnePath>) -> Response {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let fm = state.files.lock().await.clone();
    let mode = req.mode.unwrap_or(0o644);
    match fm.safe_abs_path(&req.path).and_then(|abs| {
        #[cfg(unix)]
        {
            std::fs::set_permissions(abs, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }) {
        Ok(_) => ok_json(json!({"ok":true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
#[derive(Deserialize)]
struct VisReq {
    path: String,
    is_public: bool,
}
async fn set_visibility(State(state): State<AppState>, Json(req): Json<VisReq>) -> Response {
    if req.is_public {
        if let Err(e) = mark_public_recursive(&state, &req.path).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
    } else {
        delete_visibility_tree(&state.db, &req.path).await
    }
    ok_json(json!({"ok":true}))
}
async fn mark_public_recursive(state: &AppState, rel: &str) -> Result<()> {
    let fm = state.files.lock().await.clone();
    let abs = fm.safe_abs_path(rel)?;
    for e in WalkDir::new(&abs).into_iter().filter_map(Result::ok) {
        let r = e.path().strip_prefix(&fm.root).unwrap();
        let rp = normalize_path(&format!("/{}", r.to_string_lossy()));
        upsert_visibility(&state.db, &rp, true).await?;
    }
    Ok(())
}
async fn delete_visibility_tree(db: &SqlitePool, rel: &str) {
    let n = normalize_path(rel);
    let pat = format!("{n}/%");
    let _ = sqlx::query("DELETE FROM file_visibilities WHERE file_path=? OR file_path LIKE ?")
        .bind(n)
        .bind(pat)
        .execute(db)
        .await;
}
async fn migrate_visibility(db: &SqlitePool, src: &str, dst: &str) {
    copy_visibility(db, src, dst).await;
    delete_visibility_tree(db, src).await;
}
async fn copy_visibility(db: &SqlitePool, src: &str, dst: &str) {
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
                format!("{}{}", dn, old.trim_start_matches(&sn))
            };
            let _ = upsert_visibility(db, &newp, pubv != 0).await;
        }
    }
}

#[derive(Deserialize)]
struct BatchPaths {
    paths: Vec<String>,
    target: Option<String>,
    filename: Option<String>,
}
async fn batch_delete(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    let mut failed = Vec::new();
    for p in req.paths {
        if p.is_empty() || p == "/" {
            continue;
        }
        let fm = state.files.lock().await.clone();
        if fm
            .safe_abs_path(&p)
            .map(|abs| std::fs::remove_dir_all(&abs).or_else(|_| std::fs::remove_file(&abs)))
            .is_err()
        {
            failed.push(p.clone())
        }
        delete_visibility_tree(&state.db, &p).await;
    }
    if failed.is_empty() {
        ok_json(json!({"ok":true}))
    } else {
        (
            StatusCode::MULTI_STATUS,
            Json(json!({"ok":false,"failed":failed})),
        )
            .into_response()
    }
}
async fn batch_move(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    batch_move_copy(state, req, true).await
}
async fn batch_copy(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
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
            Path::new(&sn)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        let resp = if mv {
            move_one(&state, &src, &dst).await
        } else {
            copy_one(&state, &src, &dst).await
        };
        if !resp.status().is_success() {
            failed.push(src)
        }
    }
    if !blocked.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "cannot move/copy a folder into itself or its subdirectory",
        );
    }
    if failed.is_empty() {
        ok_json(json!({"ok":true}))
    } else {
        (
            StatusCode::MULTI_STATUS,
            Json(json!({"ok":false,"failed":failed})),
        )
            .into_response()
    }
}
async fn batch_download(State(state): State<AppState>, Json(req): Json<BatchPaths>) -> Response {
    let fm = state.files.lock().await.clone();
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        for p in req.paths {
            if let Ok(abs) = fm.safe_abs_path(&p) {
                let name = Path::new(&p)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let _ = zip_add_lstat(&mut zw, &abs, &name);
            }
        }
        let _ = zw.finish();
    }
    let fname = req.filename.unwrap_or("download.zip".into());
    let fname = if fname.to_lowercase().ends_with(".zip") {
        fname
    } else {
        format!("{fname}.zip")
    };
    download_bytes(buf.into_inner(), "application/zip", &fname)
}


async fn list_public_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    if p == "/" {
        let rows = sqlx::query("SELECT file_path FROM file_visibilities WHERE is_public=1")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        let fm = state.files.lock().await.clone();
        let mut list = Vec::new();
        for r in rows {
            let rel: String = r.get(0);
            let parent = Path::new(&rel).parent().unwrap_or(Path::new("/"));
            if parent != Path::new("/") && is_public(&state.db, &parent.to_string_lossy()).await {
                continue;
            }
            if let Ok(abs) = fm.safe_abs_path(&rel) {
                if let Ok(fi) = file_info(&state.db, &abs, &rel).await {
                    list.push(fi)
                }
            }
        }
        ok_json(json!({"files":list,"path":p}))
    } else {
        match list_dir(&state, &p).await {
            Ok(v) => ok_json(
                json!({"files":v.into_iter().filter(|f|f.is_public).collect::<Vec<_>>(),"path":p}),
            ),
            Err(_) => ok_json(json!({"files":[],"path":p})),
        }
    }
}
async fn serve_public_file(
    State(state): State<AppState>,
    AxPath(path): AxPath<String>,
) -> Response {
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
            Ok(v) => ok_json(
                json!({"files":v.into_iter().filter(|f|f.is_public).collect::<Vec<_>>(),"path":rel}),
            ),
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    } else {
        serve_file_path(Ok(abs), false).await
    }
}
async fn download_public_file(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> Response {
    let p = q.path.unwrap_or_default();
    if !is_public(&state.db, &p).await {
        return json_error(StatusCode::FORBIDDEN, "not public");
    }
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&p), true).await
}

#[derive(Deserialize)]
struct ShareReq {
    path: String,
    is_dir: bool,
    expire_in: Option<i64>,
    max_views: Option<i64>,
}
async fn create_share(State(state): State<AppState>, req0: Request<Body>) -> Response {
    let user = req_user(&req0);
    let b = axum::body::to_bytes(req0.into_body(), usize::MAX)
        .await
        .unwrap();
    let req: ShareReq = serde_json::from_slice(&b).unwrap();
    let code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let exp = req
        .expire_in
        .filter(|v| *v > 0)
        .map(|s| (Utc::now() + chrono::Duration::seconds(s)).to_rfc3339());
    let now = now_string();
    match sqlx::query("INSERT INTO share_links (code,file_path,is_dir,user_id,expires_at,max_views,view_count,created_at) VALUES (?,?,?,?,?,?,0,?)").bind(&code).bind(&req.path).bind(req.is_dir as i64).bind(user.id).bind(&exp).bind(req.max_views.unwrap_or(0)).bind(now).execute(&state.db).await{Ok(r)=>{let link=get_share_by_id(&state.db,r.last_insert_rowid()).await.unwrap();Json(link).into_response()},Err(e)=>json_error(StatusCode::INTERNAL_SERVER_ERROR,e)}
}
async fn get_share_by_id(db: &SqlitePool, id: i64) -> Result<ShareLink> {
    row_to_share(
        sqlx::query("SELECT * FROM share_links WHERE id=?")
            .bind(id)
            .fetch_one(db)
            .await?,
    )
}
fn row_to_share(r: sqlx::sqlite::SqliteRow) -> Result<ShareLink> {
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
async fn list_shares(State(state): State<AppState>, req: Request<Body>) -> Response {
    let user = req_user(&req);
    let rows = sqlx::query("SELECT * FROM share_links WHERE user_id=?")
        .bind(user.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    Json(
        rows.into_iter()
            .filter_map(|r| row_to_share(r).ok())
            .collect::<Vec<_>>(),
    )
    .into_response()
}
async fn delete_share(
    State(state): State<AppState>,
    AxPath(id): AxPath<i64>,
    req: Request<Body>,
) -> Response {
    let user = req_user(&req);
    let _ = sqlx::query("DELETE FROM share_links WHERE id=? AND user_id=?")
        .bind(id)
        .bind(user.id)
        .execute(&state.db)
        .await;
    ok_json(json!({"ok":true}))
}
async fn get_share(db: &SqlitePool, code: &str, count: bool) -> Result<ShareLink> {
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
            return Err(anyhow!("share link has expired"));
        }
    }
    if l.max_views > 0 && l.view_count >= l.max_views {
        return Err(anyhow!("share link has reached maximum views"));
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
async fn access_share(
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
            format!(
                "{}/{}",
                link.file_path,
                normalize_path(&sp).trim_start_matches('/')
            )
        };
        let list = list_dir(&state, &lp).await.unwrap_or_default();
        ok_json(json!({"files":list,"is_dir":true,"code":link.code,"file_path":link.file_path}))
    } else {
        ok_json(json!({"is_dir":false,"code":link.code,"file_path":link.file_path}))
    }
}
async fn download_share(
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
            Some(s) => format!(
                "{}/{}",
                link.file_path,
                normalize_path(&s).trim_start_matches('/')
            ),
            None => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "subpath required for directory share",
                );
            }
        }
    } else {
        link.file_path
    };
    let fm = state.files.lock().await.clone();
    serve_file_path(fm.safe_abs_path(&path), true).await
}
async fn serve_share_raw(State(state): State<AppState>, AxPath(code): AxPath<String>) -> Response {
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

async fn serve_file_path(p: Result<PathBuf>, attachment: bool) -> Response {
    let abs = match p {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let data = match fs::read(&abs).await {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "not found"),
    };
    let mime = mime_guess::from_path(&abs)
        .first_or_octet_stream()
        .to_string();
    let name = abs.file_name().unwrap_or_default().to_string_lossy();
    let disp = if attachment { "attachment" } else { "inline" };
    let mut resp = (StatusCode::OK, data).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{disp}; filename=\"{name}\"")).unwrap(),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp
}
fn download_bytes(data: Vec<u8>, mime: &str, name: &str) -> Response {
    let mut resp = (StatusCode::OK, data).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")).unwrap(),
    );
    resp
}

async fn detect_file_type(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
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
            ok_json(
                json!({"text":text,"mime": if text{"text/plain; charset=utf-8"}else{"application/octet-stream"}}),
            )
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, e),
    }
}
async fn search_files(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
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
        if res.len() >= 200 {
            break;
        }
        if e.file_name().to_string_lossy().to_lowercase().contains(&kw) {
            let rel = e.path().strip_prefix(&root).unwrap();
            res.push(SearchResult {
                name: e.file_name().to_string_lossy().to_string(),
                path: normalize_path(&format!("/{}", rel.to_string_lossy())),
                is_dir: e.file_type().is_dir(),
            });
        }
    }
    ok_json(json!({"results":res}))
}
async fn list_dir_tree(State(state): State<AppState>, Query(q): Query<PathQuery>) -> Response {
    let p = q.path.unwrap_or("/".into());
    match list_dir(&state, &p).await {
        Ok(v) => ok_json(
            json!({"dirs":v.into_iter().filter(|x|x.is_dir).map(|x|json!({"name":x.name,"path":x.path,"is_dir":true})).collect::<Vec<_>>(),"path":p}),
        ),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn upload_folder(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
    mut mp: Multipart,
) -> Response {
    let dir = q.path.unwrap_or("/".into());
    let mut failed = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() != Some("files") {
            continue;
        }
        let rel = field.file_name().map(|s| s.to_string()).unwrap_or_default();
        let clean = normalize_path(&rel).trim_start_matches('/').to_string();
        match field.bytes().await {
            Ok(b) => {
                if write_rel(&state, &format!("{dir}/{clean}"), b)
                    .await
                    .is_err()
                {
                    failed.push(clean)
                }
            }
            Err(_) => failed.push(clean),
        }
    }
    if failed.is_empty() {
        ok_json(json!({"ok":true}))
    } else {
        (
            StatusCode::MULTI_STATUS,
            Json(json!({"ok":true,"failed":failed})),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
struct CompressReq {
    paths: Vec<String>,
    format: Option<String>,
    output: Option<String>,
    dir: Option<String>,
}
async fn compress_files(
    State(state): State<AppState>,
    Json(mut req): Json<CompressReq>,
) -> Response {
    let fmt_str = req.format.take().unwrap_or("zip".into());
    let dir = req.dir.unwrap_or("/".into());
    let mut out = req.output.unwrap_or("archive".into());
    let fmt = match fmt_str.as_str() {
        "tar" => {
            if !out.ends_with(".tar") { out.push_str(".tar") }
            "tar"
        }
        "tar.gz" => {
            if !out.ends_with(".tar.gz") { out.push_str(".tar.gz") }
            "tar.gz"
        }
        _ => {
            if !out.ends_with(".zip") { out.push_str(".zip") }
            "zip"
        }
    };
    let fm = state.files.lock().await.clone();

    // 收集有效路径（与 Go 版对齐：用文件/目录自身名称作为压缩包内路径前缀）
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
    if let Some(p) = out_abs.parent() {
        let _ = std::fs::create_dir_all(p);
    }

    let out_clone = out.clone();
    let result: Result<()> = tokio::task::spawn_blocking(move || -> Result<()> {
        let file = std::fs::File::create(&out_abs)?;
        match fmt {
            "zip" => {
                let mut zw = ZipWriter::new(file);
                for e in entries {
                    zip_add_lstat(&mut zw, &e.abs, &e.arc_name)?;
                }
                zw.finish()?;
            }
            _ => {
                // tar or tar.gz
                if fmt == "tar.gz" {
                    let enc = GzEncoder::new(file, Compression::default());
                    let mut tw = TarBuilder::new(enc);
                    tw.follow_symlinks(false); // 不跟随符号链接，与 Go Lstat 对齐
                    for e in entries {
                        tar_add(&mut tw, &e.abs, &e.arc_name)?;
                    }
                    tw.into_inner()?.finish()?;
                } else {
                    let mut tw = TarBuilder::new(file);
                    tw.follow_symlinks(false);
                    for e in entries {
                        tar_add(&mut tw, &e.abs, &e.arc_name)?;
                    }
                    tw.finish()?;
                }
            }
        }
        Ok(())
    }).await.map_err(|e| anyhow!(e))?;

    match result {
        Ok(_) => ok_json(json!({"ok":true,"output":out_clone})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// zip 压缩辅助（使用 Lstat 不跟随符号链接，与 Go 版对齐）
fn zip_add_lstat<W: Write + std::io::Seek>(
    zw: &mut ZipWriter<W>,
    abs: &Path,
    name: &str,
) -> zip::result::ZipResult<()> {
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
            .unix_permissions(info.permissions().mode() as u16);
        zw.start_file(name, opts)?;
        let mut f = std::fs::File::open(abs)?;
        std::io::copy(&mut f, zw)?;
    }
    // 符号链接跳过（与 Go 版 Lstat + !info.IsDir() 等价）
    Ok(())
}

/// tar 压缩辅助（递归，不跟随符号链接）
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
#[derive(Deserialize)]
struct DecompressReq {
    path: String,
    dir: Option<String>,
}
async fn decompress_file(
    State(state): State<AppState>,
    Json(req): Json<DecompressReq>,
) -> Response {
    let fm = state.files.lock().await.clone();
    let abs = match fm.safe_abs_path(&req.path) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let dest_rel = req.dir.unwrap_or_else(|| {
        Path::new(&req.path)
            .parent()
            .map(|p| {
                let s = p.to_string_lossy();
                if s.is_empty() || s == "." { "/".into() } else { s.into_owned() }
            })
            .unwrap_or_else(|| "/".into())
    });
    let dest = match fm.safe_abs_path(&dest_rel) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let name = abs.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

    // safe_extract：防 zip-slip 路径穿越（与 Go 版 safeExtract 对齐）
    fn safe_extract(dest: &Path, entry_name: &str, reader: &mut dyn Read, mode: u32, is_dir: bool) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        // 清理路径，防止 ../ 穿越
        let clean = dest.join(Path::new(&format!("/{}", entry_name)).components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect::<PathBuf>());
        if !clean.starts_with(dest) {
            return Ok(()); // 跳过非法路径
        }
        if is_dir {
            return std::fs::create_dir_all(&clean);
        }
        if let Some(parent) = clean.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let perm = std::fs::Permissions::from_mode((mode & 0o777) | 0o600);
        let mut f = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true)
            .open(&clean)?;
        f.set_permissions(perm)?;
        std::io::copy(reader, &mut f)?;
        Ok(())
    }

    let result: Result<()> = tokio::task::spawn_blocking(move || -> Result<()> {
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
            // 单文件 .gz
            let f = std::fs::File::open(&abs)?;
            let mut gz = GzDecoder::new(f);
            let out_name = abs.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            safe_extract(&dest, &out_name, &mut gz, 0o644, false)?;
        } else {
            return Err(anyhow!("unsupported archive format"));
        }
        Ok(())
    }).await.map_err(|e| anyhow!(e))?.map_err(|e| anyhow!(e));

    match result {
        Ok(_) => ok_json(json!({"ok":true})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
#[derive(Deserialize)]
struct FetchReq {
    url: String,
    filename: Option<String>,
    dir: Option<String>,
}
// GitHub 加速代理前缀列表（与 Go 版对齐）
const GITHUB_PROXY_PREFIXES: &[&str] = &[
    "https://gh-proxy.com/",
    "https://gh.ddlc.top/",
    "https://ghproxy.it/",
];

fn is_github_url(raw: &str) -> bool {
    let github_hosts = [
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
        "releases.githubusercontent.com",
        "gist.githubusercontent.com",
        "gist.github.com",
    ];
    if let Ok(u) = url::Url::parse(raw) {
        if let Some(host) = u.host_str() {
            let h = host.to_lowercase();
            for gh in &github_hosts {
                if h == *gh || h.ends_with(&format!(".{}", gh)) {
                    return true;
                }
            }
        }
    }
    false
}

async fn fetch_url(State(state): State<AppState>, Json(req): Json<FetchReq>) -> Response {
    if let Err(e) = validate_public_url(&req.url).await {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    let fm = state.files.lock().await.clone();
    let dir = match fm.safe_abs_path(&req.dir.clone().unwrap_or("/".into())) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let _ = fs::create_dir_all(&dir).await;

    // 从原始 URL 推断文件名（避免代理前缀影响）
    let fname = req.filename.clone().unwrap_or_else(|| {
        url::Url::parse(&req.url)
            .ok()
            .and_then(|u| u.path_segments()?.last().map(str::to_string))
            .filter(|s| !s.is_empty() && *s != "." && *s != "/")
            .unwrap_or("download".into())
    });
    let out = dir.join(safe_name(&fname));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1800))
        .redirect(Policy::limited(10))
        .build()
        .unwrap();

    // 构建待尝试 URL 列表：先直连，若是 GitHub 链接则追加代理
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
                match r.bytes().await {
                    Ok(b) => match fs::write(&out, b).await {
                        Ok(_) => return ok_json(json!({"ok":true})),
                        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
                    },
                    Err(e) => {
                        last_err = e.to_string();
                    }
                }
            }
            Ok(r) => {
                last_err = format!("remote returned {} [{}]", r.status(), try_url);
            }
            Err(e) => {
                last_err = format!("fetch failed [{}]: {}", try_url, e);
            }
        }
    }
    json_error(StatusCode::INTERNAL_SERVER_ERROR, last_err)
}
async fn validate_public_url(raw: &str) -> Result<()> {
    let u = url::Url::parse(raw)?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(anyhow!("only http/https URLs are allowed"));
    }
    let host = u.host_str().ok_or_else(|| anyhow!("missing host"))?;
    if host.eq_ignore_ascii_case("localhost") {
        return Err(anyhow!(
            "requests to private/internal addresses are not allowed"
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(anyhow!(
                "requests to private/internal addresses are not allowed"
            ));
        }
    }
    Ok(())
}
fn is_private_ip(ip: IpAddr) -> bool {
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

async fn get_webdav_settings(State(state): State<AppState>) -> Response {
    let s = get_settings(&state.db).await.unwrap();
    ok_json(
        json!({"webdav_enabled":s.webdav_enabled,"webdav_sub_path":s.webdav_sub_path,"webdav_username":s.webdav_username,"webdav_has_password":!s.webdav_password_enc.is_empty()}),
    )
}
#[derive(Deserialize)]
struct WebdavReq {
    webdav_enabled: bool,
    webdav_sub_path: Option<String>,
    webdav_username: Option<String>,
    webdav_password: Option<String>,
}
async fn update_webdav_settings(
    State(state): State<AppState>,
    Json(req): Json<WebdavReq>,
) -> Response {
    let mut enc = None;
    if let Some(p) = req.webdav_password.filter(|s| !s.is_empty()) {
        let h = hash(p, DEFAULT_COST).unwrap();
        enc = Some(encrypt(&state.master_key, &h).unwrap());
    }
    let mut q =
        "UPDATE settings SET webdav_enabled=?,webdav_sub_path=?,webdav_username=?".to_string();
    if enc.is_some() {
        q.push_str(",webdav_password_enc=?");
    }
    q.push_str(" WHERE id=1");
    let mut query = sqlx::query(&q)
        .bind(req.webdav_enabled as i64)
        .bind(req.webdav_sub_path.unwrap_or_default())
        .bind(req.webdav_username.unwrap_or_default());
    if let Some(e) = enc {
        query = query.bind(e)
    }
    let _ = query.execute(&state.db).await;
    get_webdav_settings(State(state)).await
}
async fn webdav_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
) -> Response {
    let headers = req.headers().clone();
    let s = get_settings(&state.db).await.unwrap();
    if !s.webdav_enabled {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Basic ") {
        return basic_unauth();
    }
    if !state.webdav_limiter.allow(real_ip(&headers, addr)).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let decoded = general_purpose::STANDARD
        .decode(&auth[6..])
        .unwrap_or_default();
    let pair = String::from_utf8_lossy(&decoded);
    let (u, p) = pair.split_once(':').unwrap_or(("", ""));
    let expected = if s.webdav_username.is_empty() {
        sqlx::query("SELECT username FROM users LIMIT 1")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| r.get(0))
            .unwrap_or_default()
    } else {
        s.webdav_username.clone()
    };
    if u != expected {
        return basic_unauth();
    }
    let pass_ok = if !s.webdav_password_enc.is_empty() {
        decrypt_opt(&state.master_key, &s.webdav_password_enc)
            .map(|h| verify(p, h.as_str()).unwrap_or(false))
            .unwrap_or(false)
    } else {
        sqlx::query("SELECT password FROM users WHERE username=?")
            .bind(u)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| verify(p, r.get::<String, _>(0).as_str()).unwrap_or(false))
            .unwrap_or(false)
    };
    if !pass_ok {
        return basic_unauth();
    }
    let webdav_sub_path = if s.webdav_sub_path.is_empty() {
        "webdav"
    } else {
        s.webdav_sub_path.trim_start_matches('/')
    };
    let base = state.files.lock().await.root().join(webdav_sub_path);
    let _ = fs::create_dir_all(&base).await;
    let path = req.uri().path().trim_start_matches("/dav");
    let abs = base.join(path.trim_start_matches('/'));
    if !abs.starts_with(&base) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match req.method().as_str() {
        "OPTIONS" => {
            let mut r = StatusCode::OK.into_response();
            r.headers_mut()
                .insert("DAV", HeaderValue::from_static("1, 2"));
            r
        }
        "GET" | "HEAD" => serve_file_path(Ok(abs), false).await,
        "PUT" => {
            if let Some(p) = abs.parent() {
                let _ = fs::create_dir_all(p).await;
            }
            let b = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .unwrap_or_default();
            match fs::write(abs, b).await {
                Ok(_) => StatusCode::CREATED.into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        "DELETE" => match fs::remove_dir_all(&abs).await {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(_) => match fs::remove_file(&abs).await {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            },
        },
        "MKCOL" => match fs::create_dir_all(abs).await {
            Ok(_) => StatusCode::CREATED.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        "PROPFIND" => dav_propfind(&base, path, &abs).await,
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}
fn basic_unauth() -> Response {
    let mut r = StatusCode::UNAUTHORIZED.into_response();
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"CloudOne WebDAV\""),
    );
    r
}
async fn dav_propfind(_base: &Path, rel: &str, abs: &Path) -> Response {
    let md = match fs::metadata(abs).await {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut body =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    body.push_str(&format!("<D:response><D:href>/dav{}</D:href><D:propstat><D:prop>{}<D:getcontentlength>{}</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>", rel, if md.is_dir(){"<D:resourcetype><D:collection/></D:resourcetype>"}else{"<D:resourcetype/>"}, md.len()));
    body.push_str("</D:multistatus>");
    let mut r = (StatusCode::MULTI_STATUS, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    r
}

// ── PTY 辅助函数（对应 Go 版 internal/terminal/terminal.go）─────────────────

/// 打开一个 PTY master/slave 对，返回 master fd。
/// 在 Linux 上通过 /dev/ptmx 实现，与 Go 版逻辑完全对应。
fn open_pty() -> std::io::Result<RawFd> {
    let master_fd = unsafe {
        libc::open(
            b"/dev/ptmx\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if master_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // 解锁 slave PTY
    let unlock: libc::c_int = 0;
    if unsafe { libc::ioctl(master_fd, libc::TIOCSPTLCK, &unlock) } < 0 {
        unsafe { libc::close(master_fd) };
        return Err(std::io::Error::last_os_error());
    }
    Ok(master_fd)
}

fn get_slave_name(master_fd: RawFd) -> std::io::Result<OsString> {
    let mut ptn: libc::c_uint = 0;
    if unsafe { libc::ioctl(master_fd, libc::TIOCGPTN, &mut ptn) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OsString::from(format!("/dev/pts/{}", ptn)))
}

fn resize_pty(master_fd: RawFd, rows: u16, cols: u16) {
    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    let ws = Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
}

async fn terminal_ws(
    State(state): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    // WebSocket 无法携带 Authorization header，从 ?token= 查询参数取 JWT
    let token_str = q.get("token").cloned().unwrap_or_default();
    if token_str.is_empty() {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let data = match jsonwebtoken::decode::<Claims>(
        &token_str,
        &jsonwebtoken::DecodingKey::from_secret(&state.jwt_secret),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    ) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let user = match get_user_by_id(&state.db, data.claims.sub).await {
        Ok(u) => u,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "user not found"),
    };
    if user.token_version != data.claims.version {
        return json_error(StatusCode::UNAUTHORIZED, "token revoked");
    }
    ws.on_upgrade(handle_ws)
}

async fn handle_ws(mut socket: WebSocket) {
    // 打开 PTY master
    let master_fd = match tokio::task::spawn_blocking(open_pty).await {
        Ok(Ok(fd)) => fd,
        _ => {
            let _ = socket.send(Message::Text(
                json!({"type":"error","data":"Failed to open PTY"}).to_string().into(),
            )).await;
            return;
        }
    };

    // 获取 slave 设备路径
    let slave_path = match get_slave_name(master_fd) {
        Ok(p) => p,
        Err(e) => {
            unsafe { libc::close(master_fd) };
            let _ = socket.send(Message::Text(
                json!({"type":"error","data": format!("PTY slave error: {e}")}).to_string().into(),
            )).await;
            return;
        }
    };

    // 打开 slave fd（子进程 stdin/stdout/stderr 用）
    let slave_cpath = std::ffi::CString::new(slave_path.to_string_lossy().as_ref()).unwrap_or_default();
    let slave_fd = unsafe {
        libc::open(slave_cpath.as_ptr(), libc::O_RDWR | libc::O_NOCTTY)
    };
    if slave_fd < 0 {
        unsafe { libc::close(master_fd) };
        let _ = socket.send(Message::Text(
            json!({"type":"error","data":"Failed to open PTY slave"}).to_string().into(),
        )).await;
        return;
    }

    let shell = if Path::new("/bin/bash").exists() { "/bin/bash" } else { "/bin/sh" };

    // 构建命令，slave fd 作为 stdin/stdout/stderr
    let mut cmd = Command::new(shell);
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    // 通过 pre_exec 在子进程里做 setsid + 设置控制终端
    unsafe {
        let sfd = slave_fd;
        cmd.pre_exec(move || {
            // 新建会话
            libc::setsid();
            // 将 slave 设置为控制终端
            libc::ioctl(sfd, libc::TIOCSCTTY, 0 as libc::c_int);
            // 重定向 stdin/stdout/stderr 到 slave
            libc::dup2(sfd, 0);
            libc::dup2(sfd, 1);
            libc::dup2(sfd, 2);
            if sfd > 2 {
                libc::close(sfd);
            }
            Ok(())
        });
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe { libc::close(slave_fd); libc::close(master_fd); }
            let _ = socket.send(Message::Text(
                json!({"type":"error","data": format!("Failed to start shell: {e}")}).to_string().into(),
            )).await;
            return;
        }
    };

    // 父进程关闭 slave（子进程已继承）
    unsafe { libc::close(slave_fd) };

    let _ = socket.send(Message::Text(
        json!({"type":"connected"}).to_string().into(),
    )).await;

    let master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let master_fd_clone = master_fd;

    let (mut tx, mut rx) = socket.split();

    // PTY → WebSocket：在独立线程中阻塞读
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut f = master_file;
        let mut buf = [0u8; 4096];
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // 转发 PTY 输出到 WebSocket
    let ws_out = tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            let text = json!({"type":"output","data": String::from_utf8_lossy(&data)}).to_string();
            if tx.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // WebSocket → PTY（主循环）
    while let Some(Ok(Message::Text(t))) = rx.next().await {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            match v["type"].as_str().unwrap_or("") {
                "input" => {
                    let data = v["data"].as_str().unwrap_or("").as_bytes().to_vec();
                    let fd = master_fd_clone;
                    tokio::task::spawn_blocking(move || {
                        unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
                    }).await.ok();
                }
                "resize" => {
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = if rows == 0 { 24 } else { rows };
                    let cols = if cols == 0 { 80 } else { cols };
                    resize_pty(master_fd_clone, rows, cols);
                }
                _ => {}
            }
        }
    }

    let _ = child.kill().await;
    ws_out.abort();
    // master_fd 已被 File 接管，close 由 drop 触发（线程中的 File 在读完后 drop）
}

async fn static_fallback(req: Request<Body>) -> Response {
    let mut path = req.uri().path().trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".into()
    }

    if let Some((data, mime)) =
        embedded_frontend::get(&path).or_else(|| embedded_frontend::get("index.html"))
    {
        return embedded_frontend_response(data, mime);
    }

    let candidate = PathBuf::from("frontend/dist").join(&path);
    let p = if candidate.exists() {
        candidate
    } else {
        PathBuf::from("frontend/dist/index.html")
    };
    if p.exists() {
        serve_file_path(Ok(p), false).await
    } else {
        (
            StatusCode::OK,
            "CloudOne frontend is not built. Run `cd frontend && npm run build` before compiling the Rust binary.",
        )
            .into_response()
    }
}

fn embedded_frontend_response(data: &'static [u8], mime: &'static str) -> Response {
    let mut resp = Response::new(Body::from(axum::body::Bytes::from_static(data)));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp
}

fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(general_purpose::STANDARD.encode(out))
}
fn decrypt_opt(key: &[u8; 32], enc: &str) -> Option<String> {
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
fn real_ip(headers: &HeaderMap, addr: std::net::SocketAddr) -> String {
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
async fn ensure_conf(data: &Path) -> Result<()> {
    let p = data.join("conf.ini");
    if !p.exists() {
        fs::write(p, "[server]\nhost=0.0.0.0\nport=6677\n").await?;
    }
    Ok(())
}
async fn load_conf(data: &Path) -> Result<(String, String)> {
    let s = fs::read_to_string(data.join("conf.ini"))
        .await
        .unwrap_or_default();
    let mut host = "0.0.0.0".to_string();
    let mut port = "6677".to_string();
    for l in s.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("host=") {
            host = v.to_string()
        }
        if let Some(v) = l.strip_prefix("port=") {
            port = v.to_string()
        }
    }
    Ok((host, port))
}
