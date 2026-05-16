use anyhow::Result;
use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::Next,
    response::Response,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::Deserialize;
use serde_json::json;

use crate::db::{get_user_by_id, row_to_user};
use crate::types::{AppState, Claims, User};
use crate::util::{json_error, now_string, ok_json, real_ip, unix_now};

pub fn gen_token(state: &AppState, user: &User) -> Result<String> {
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

pub async fn auth_middleware(
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

pub fn req_user(req: &Request<Body>) -> User {
    req.extensions().get::<User>().unwrap().clone()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn auth_status(State(state): State<AppState>) -> Response {
    let c: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    ok_json(json!({"setup": c > 0}))
}

#[derive(Deserialize)]
pub struct AuthReq {
    pub username: String,
    pub password: String,
}

pub async fn setup(State(state): State<AppState>, Json(req): Json<AuthReq>) -> Response {
    let c: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if c > 0 {
        return json_error(StatusCode::BAD_REQUEST, "already setup");
    }
    let password = req.password.clone();
    let h = match tokio::task::spawn_blocking(move || hash(password, DEFAULT_COST)).await {
        Ok(Ok(v)) => v,
        Ok(Err(_)) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to hash password")
        }
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let c2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if c2 > 0 {
        return json_error(StatusCode::BAD_REQUEST, "already setup");
    }
    let now = now_string();
    let id = match sqlx::query(
        "INSERT INTO users (username,password,token_version,created_at,updated_at) VALUES (?,?,?,?,?)",
    )
    .bind(&req.username)
    .bind(h)
    .bind(0i64)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    {
        Ok(r) => r.last_insert_rowid(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let user = get_user_by_id(&state.db, id).await.unwrap();
    let token = gen_token(&state, &user).unwrap();
    ok_json(json!({"token": token, "user": user}))
}

pub async fn login(
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
    ok_json(json!({"token": token, "user": user}))
}

pub async fn get_user(req: Request<Body>) -> Response {
    ok_json(json!(req_user(&req)))
}

#[derive(Deserialize)]
pub struct UpdateUserReq {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub async fn update_user(State(state): State<AppState>, req0: Request<Body>) -> Response {
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
    let mut resp = json!({"user": user});
    if password_changed {
        resp["token"] = json!(gen_token(&state, &user).unwrap());
    }
    ok_json(resp)
}
