use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use bcrypt::verify;
use rand::RngCore;
use tokio::fs;

use crate::db::get_settings;
use crate::handler::serve_file_path;
use crate::types::AppState;
use crate::util::real_ip;

pub async fn webdav_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
) -> Response {
    let headers = req.headers().clone();
    let s = get_settings(&state.db).await.unwrap();
    if !s.webdav_enabled {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !auth.starts_with("Basic ") {
        return basic_unauth();
    }
    if !state.webdav_limiter.allow(real_ip(&headers, addr)).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let decoded = general_purpose::STANDARD.decode(&auth[6..]).unwrap_or_default();
    let pair = String::from_utf8_lossy(&decoded);
    let (u, p) = pair.split_once(':').unwrap_or(("", ""));

    let expected: String = if s.webdav_username.is_empty() {
        sqlx::query("SELECT username FROM users LIMIT 1")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| { use sqlx::Row; r.get(0) })
            .unwrap_or_default()
    } else {
        s.webdav_username.clone()
    };
    if u != expected {
        return basic_unauth();
    }
    let pass_ok = if !s.webdav_password_enc.is_empty() {
        crate::util::decrypt_opt(&state.master_key, &s.webdav_password_enc)
            .map(|h| verify(p, h.as_str()).unwrap_or(false))
            .unwrap_or(false)
    } else {
        sqlx::query("SELECT password FROM users WHERE username=?")
            .bind(u)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| { use sqlx::Row; verify(p, r.get::<String, _>(0).as_str()).unwrap_or(false) })
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
            r.headers_mut().insert("DAV", HeaderValue::from_static("1, 2"));
            r.headers_mut().insert(
                header::HeaderName::from_static("allow"),
                HeaderValue::from_static("OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK"),
            );
            r.headers_mut().insert(
                header::HeaderName::from_static("ms-author-via"),
                HeaderValue::from_static("DAV"),
            );
            r
        }
        "GET" | "HEAD" => serve_file_path(Ok(abs), false).await,
        "PUT" => {
            if let Some(p) = abs.parent() { let _ = fs::create_dir_all(p).await; }
            let b = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();
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
        "PROPFIND" => {
            let depth = req.headers()
                .get("Depth")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("1")
                .to_string();
            dav_propfind(&base, path, &abs, &depth).await
        }
        "COPY" | "MOVE" => {
            let dest_header = req.headers().get("Destination")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if dest_header.is_empty() {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let dest_path = if let Some(idx) = dest_header.find("/dav") {
                dest_header[idx + 4..].to_string()
            } else {
                dest_header.clone()
            };
            let abs_dest = base.join(dest_path.trim_start_matches('/'));
            if !abs_dest.starts_with(&base) {
                return StatusCode::FORBIDDEN.into_response();
            }
            if let Some(p) = abs_dest.parent() { let _ = fs::create_dir_all(p).await; }
            let is_copy = req.method().as_str() == "COPY";
            if is_copy {
                match copy_path_recursive(&abs, &abs_dest) {
                    Ok(_) => StatusCode::CREATED.into_response(),
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            } else {
                match std::fs::rename(&abs, &abs_dest) {
                    Ok(_) => StatusCode::CREATED.into_response(),
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        }
        "LOCK" => {
            let mut token_bytes = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let token = format!("urn:uuid:cloudone-lock-{}", hex::encode(token_bytes));
            let xml = format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktype><D:write/></D:locktype>
<D:lockscope><D:exclusive/></D:lockscope>
<D:depth>infinity</D:depth>
<D:timeout>Second-3600</D:timeout>
<D:locktoken><D:href>{token}</D:href></D:locktoken>
</D:activelock></D:lockdiscovery></D:prop>"#,
                token = token
            );
            let mut r = (StatusCode::OK, xml).into_response();
            r.headers_mut().insert("Lock-Token", HeaderValue::from_str(&format!("<{}>", token)).unwrap());
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
            r
        }
        "UNLOCK" => StatusCode::NO_CONTENT.into_response(),
        "PROPPATCH" => {
            let xml = r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"></D:multistatus>"#;
            let mut r = (StatusCode::MULTI_STATUS, xml).into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
            r
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn copy_path_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    let meta = src.symlink_metadata()?;
    if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_path_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

fn basic_unauth() -> Response {
    let mut r = StatusCode::UNAUTHORIZED.into_response();
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"CloudOne WebDAV\""),
    );
    r
}

async fn dav_propfind(_base: &std::path::Path, rel: &str, abs: &std::path::Path, depth: &str) -> Response {
    let md = match fs::metadata(abs).await {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut body = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    write_propfind_entry(&mut body, rel, &md);
    if md.is_dir() && depth != "0" {
        if let Ok(mut rd) = fs::read_dir(abs).await {
            let child_base = if rel.ends_with('/') { rel.to_string() } else { format!("{}/", rel) };
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Ok(child_md) = entry.metadata().await {
                    let child_name = entry.file_name().to_string_lossy().into_owned();
                    let child_rel = format!("{}{}", child_base, child_name);
                    write_propfind_entry(&mut body, &child_rel, &child_md);
                }
            }
        }
    }
    body.push_str("</D:multistatus>");
    let mut r = (StatusCode::MULTI_STATUS, body).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    r
}

fn write_propfind_entry(body: &mut String, rel: &str, md: &std::fs::Metadata) {
    let href = if md.is_dir() && !rel.ends_with('/') { format!("/dav{}/", rel) } else { format!("/dav{}", rel) };
    let resource_type = if md.is_dir() { "<D:resourcetype><D:collection/></D:resourcetype>" } else { "<D:resourcetype/>" };
    let content_length = if md.is_dir() { String::new() } else { format!("<D:getcontentlength>{}</D:getcontentlength>", md.len()) };
    let mod_time = md.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| {
            let secs = d.as_secs();
            let days = secs / 86400;
            let tod = secs % 86400;
            let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
            let mut y = 1970u64;
            let mut rem = days;
            loop {
                let diy = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
                if rem < diy { break; }
                rem -= diy; y += 1;
            }
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let mdays = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut mo = 0usize;
            for (i, &md) in mdays.iter().enumerate() { if rem < md { mo = i + 1; break; } rem -= md; }
            let dom = rem + 1;
            let dow = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][((days + 4) % 7) as usize];
            let mon = ["","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][mo];
            format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT", dow, dom, mon, y, h, m, s)
        })
        .unwrap_or_default();
    let display_name = rel.trim_end_matches('/').rsplit('/').next().unwrap_or(rel);
    body.push_str(&format!(
        "<D:response><D:href>{href}</D:href><D:propstat><D:prop>{resource_type}{content_length}<D:getlastmodified>{mod_time}</D:getlastmodified><D:displayname>{display_name}</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
    ));
}
