// Modified: built-in web console for hbbs — REST API + embedded SPA.
// Runs on its own HTTP port (default 21114) inside the hbbs process.
// Auth: single admin password (bcrypt in DB), JWT tokens (2h), login rate limiting.
use crate::common::now;
use crate::database::Database;
use crate::peer::PeerMap;
use axum::{
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use hbb_common::{log, tokio, ResultType};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::Duration};

// Embedded SPA (single-file UI under console/)
pub static CONSOLE_ASSETS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/console");

pub(crate) struct ConsoleState {
    pub pm: PeerMap,
    pub db: Database,
    pub jwt_secret: Vec<u8>,
    pub started_at: u64,
    pub http: std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>, // login rate limit
    pub geo_cache: std::sync::Mutex<std::collections::HashMap<String, serde_json::Value>>,
}

const CONSOLE_PORT: i32 = 21114;
const JWT_HOURS: u64 = 2;
const REG_TIMEOUT_MS: i64 = 30_000;

type AppState = Arc<ConsoleState>;

pub async fn start_console(pm: PeerMap, db: Database) {
    let port: i32 = crate::common::get_arg_or("CONSOLE_PORT", CONSOLE_PORT.to_string())
        .parse()
        .unwrap_or(CONSOLE_PORT);
    tokio::spawn(async move {
        if let Err(err) = run_console(pm, db, port).await {
            log::error!("console: failed to start on port {}: {}", port, err);
        }
    });
}

async fn run_console(pm: PeerMap, db: Database, port: i32) -> ResultType<()> {
    if let Err(err) = db.console_init().await {
        log::error!("console: init tables failed: {}", err);
        return Err(err);
    }
    // admin password: env CONSOLE_PASSWORD wins; otherwise generate a random one
    // on first boot and log it (must be changed via the console afterwards).
    let admin_hash = match db.console_get_config("admin_hash").await? {
        Some(h) => h,
        None => {
            let pass = match std::env::var("CONSOLE_PASSWORD") {
                Ok(p) if !p.is_empty() => {
                    log::info!("console: using admin password from CONSOLE_PASSWORD env");
                    p
                }
                _ => {
                    let p = gen_password(12);
                    log::info!("console: first boot admin password = [{}]", p);
                    p
                }
            };
            let h = bcrypt::hash(&pass, bcrypt::DEFAULT_COST).unwrap_or_default();
            db.console_set_config("admin_hash", &h).await?;
            h
        }
    };
    let jwt_secret = match db.console_get_config("jwt_secret").await? {
        Some(s) => s,
        None => {
            let s = gen_password(48);
            db.console_set_config("jwt_secret", &s).await?;
            s
        }
    };
    let state: AppState = Arc::new(ConsoleState {
        pm,
        db,
        jwt_secret: jwt_secret.into_bytes(),
        started_at: now(),
        http: Default::default(),
        geo_cache: Default::default(),
    });
    let _ = admin_hash;

    let app = Router::new()
        .route("/api/login", post(api_login))
        .route("/api/peers", get(api_peers))
        .route("/api/peers/:id", get(api_peer_detail))
        .route("/api/peers/:id/location", post(api_set_location))
        .route("/api/map", get(api_map))
        .route("/api/stats", get(api_stats))
        .route("/api/events", get(api_events))
        .route("/api/server", get(api_server))
        .route("/api/password", post(api_password));
    // static SPA (must be added after the API routes; catch-all)
    let app = app
        .layer(Extension(state))
        .fallback(get(static_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], port as u16));
    log::info!("console: web UI listening on http://{}", addr);
    let server = axum::Server::bind(&addr).serve(app.into_make_service());
    server.await?;
    Ok(())
}

fn gen_password(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rand::Rng::gen_range(&mut rng, 0..CHARS.len())] as char)
        .collect()
}

// ---------- auth helpers ----------

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn make_jwt(state: &ConsoleState) -> Result<String, String> {
    let claims = Claims {
        sub: "admin".to_owned(),
        exp: (now() + JWT_HOURS * 3600) as usize,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(&state.jwt_secret),
    )
    .map_err(|e| e.to_string())
}

fn verify_jwt(state: &ConsoleState, token: &str) -> bool {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(&state.jwt_secret),
        &validation,
    )
    .is_ok()
}

// returns Err((status, json)) when unauthorized
fn check_auth(state: &ConsoleState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
    };
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token {
        Some(t) if verify_jwt(state, t) => Ok(()),
        _ => Err(unauthorized()),
    }
}

// ---------- handlers ----------

async fn api_login(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // naive per-IP rate limit: block after 10 failures for 10 minutes
    let ip = client_ip(&headers);
    {
        let mut rl = state.http.lock().unwrap();
        if let Some((fails, since)) = rl.get(&ip) {
            if *fails >= 10 && since.elapsed() < Duration::from_secs(600) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error": "too many failed logins"})),
                ));
            }
        }
    }
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let hash = state
        .db
        .console_get_config("admin_hash")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !password.is_empty() && bcrypt::verify(password, &hash).unwrap_or(false) {
        state.http.lock().unwrap().remove(&ip);
        let token = make_jwt(&state).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e})),
            )
        })?;
        Ok(Json(json!({"token": token, "expires_in": JWT_HOURS * 3600})))
    } else {
        let mut rl = state.http.lock().unwrap();
        let entry = rl.entry(ip).or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "wrong password"})),
        ))
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next().map(|s| s.trim().to_owned()))
        .unwrap_or_else(|| "unknown".to_owned())
}

async fn api_password(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let old = body.get("old").and_then(|v| v.as_str()).unwrap_or("");
    let new = body.get("new").and_then(|v| v.as_str()).unwrap_or("");
    let hash = state
        .db
        .console_get_config("admin_hash")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !bcrypt::verify(old, &hash).unwrap_or(false) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "wrong current password"})),
        ));
    }
    if new.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "new password must be at least 8 characters"})),
        ));
    }
    state
        .db
        .console_set_config("admin_hash", &bcrypt::hash(new, bcrypt::DEFAULT_COST).unwrap_or_default())
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({"ok": true})))
}

fn internal_error(e: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    log::error!("console: {}", e);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error"})),
    )
}

fn is_online(elapsed_ms: i64) -> bool {
    elapsed_ms < REG_TIMEOUT_MS
}

/// (id, last_reg elapsed ms) of every in-memory peer
async fn in_memory_status(pm: &PeerMap) -> std::collections::HashMap<String, i64> {
    pm.list_elapsed()
        .await
        .into_iter()
        .collect::<std::collections::HashMap<String, i64>>()
}

fn peer_json(
    id: &str,
    p: &crate::database::Peer,
    elapsed: Option<i64>,
    geo: Option<&serde_json::Value>,
    manual: Option<&serde_json::Value>,
) -> serde_json::Value {
    let info: serde_json::Value = serde_json::from_str(&p.info).unwrap_or(json!({}));
    let ip = info.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let location = manual.or(geo).cloned().unwrap_or(json!(null));
    json!({
        "id": id,
        "ip": ip,
        "uuid": hex_short(&p.uuid),
        "pk": base64_short(&p.pk),
        "online": elapsed.map(is_online).unwrap_or(false),
        "last_seen": elapsed.map(|e| if is_online(e) { 0 } else { -1 }).unwrap_or(-1),
        "location": location,
    })
}

fn hex_short(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).take(8).collect()
}

fn base64_short(b: &[u8]) -> String {
    base64::encode(&b[..b.len().min(16)])
}

async fn api_peers(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let memory = in_memory_status(&state.pm).await;
    let peers = state.db.list_peers().await.map_err(internal_error)?;
    let geo = state.db.console_list_geo().await.map_err(internal_error)?;
    let manual = state.db.console_list_locations().await.map_err(internal_error)?;
    let out: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            peer_json(
                &p.id,
                p,
                memory.get(&p.id).copied(),
                geo.get(&p.info_ip()),
                manual.get(&p.id),
            )
        })
        .collect();
    Ok(Json(json!({"peers": out})))
}

async fn api_peer_detail(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let peer = state.db.get_peer(&id).await.map_err(internal_error)?;
    match peer {
        Some(p) => {
            let memory = in_memory_status(&state.pm).await;
            let geo = state.db.console_list_geo().await.map_err(internal_error)?;
            let manual = state
                .db
                .console_list_locations()
                .await
                .map_err(internal_error)?;
            Ok(Json(peer_json(
                &id,
                &p,
                memory.get(&id).copied(),
                geo.get(&p.info_ip()),
                manual.get(&id),
            )))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "peer not found"})),
        )),
    }
}

async fn api_set_location(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    if body.get("clear").and_then(|v| v.as_bool()).unwrap_or(false) {
        state
            .db
            .console_delete_location(&id)
            .await
            .map_err(internal_error)?;
        return Ok(Json(json!({"ok": true, "cleared": true})));
    }
    let getf = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let country = getf("country");
    let city = getf("city");
    let lat = body.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let lon = body.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
    state
        .db
        .console_set_location(&id, &country, &city, lat, lon)
        .await
        .map_err(internal_error)?;
    state
        .db
        .console_add_event("location", &id, &format!("{},{}", country, city))
        .await
        .ok();
    Ok(Json(json!({"ok": true})))
}

async fn api_map(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let memory = in_memory_status(&state.pm).await;
    let peers = state.db.list_peers().await.map_err(internal_error)?;
    let geo = state.db.console_list_geo().await.map_err(internal_error)?;
    let manual = state
        .db
        .console_list_locations()
        .await
        .map_err(internal_error)?;
    let mut points = Vec::new();
    let mut unknown = 0usize;
    for p in peers.iter() {
        let elapsed = memory.get(&p.id).copied();
        let manual = manual.get(&p.id).cloned();
        let ip = p.info_ip();
        let geo = geo.get(&ip).cloned();
        let loc = match (&manual, &geo) {
            (Some(m), _) => Some(m.clone()),
            (None, Some(g)) if g.get("lat").is_some() => Some(g.clone()),
            _ => None,
        };
        match loc {
            Some(l) => {
                points.push(json!({
                    "id": p.id,
                    "online": elapsed.map(is_online).unwrap_or(false),
                    "country": l.get("country").and_then(|v| v.as_str()).unwrap_or(""),
                    "city": l.get("city").and_then(|v| v.as_str()).unwrap_or(""),
                    "lat": l.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    "lon": l.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0),
                }));
            }
            None => {
                unknown += 1;
                // try GeoIP lookup (cache 24h) in the background; result lands in console_geo
                if let Some(geo_task_ip) = (!ip.is_empty()).then(|| ip.clone()) {
                    let st = state.clone();
                    tokio::spawn(async move {
                        geo_lookup(&st, &geo_task_ip).await;
                    });
                }
            }
        }
    }
    Ok(Json(json!({"points": points, "unknown": unknown})))
}

// GeoIP: ip-api.com with a 24h in-memory cache (results also persisted in console_geo)
async fn geo_lookup(state: &AppState, ip: &str) {
    {
        let cache = state.geo_cache.lock().unwrap();
        if let Some(v) = cache.get(ip) {
            if let Some(t) = v.get("_t").and_then(|v| v.as_u64()) {
                if now() - t < 3600 * 24 {
                    return;
                }
            }
        }
    }
    let ip_owned = ip.to_owned();
    let res = tokio::task::spawn_blocking(move || {
        let url = format!(
            "http://ip-api.com/json/{}?fields=country,city,lat,lon",
            ip_owned
        );
        minreq::get(&url).with_timeout(5).send().ok()
    })
    .await;
    if let Ok(Some(resp)) = res {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(resp.as_bytes()) {
            let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("");
            let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("");
            let lat = v.get("lat").and_then(|x| x.as_f64());
            let lon = v.get("lon").and_then(|x| x.as_f64());
            if let (Some(lat), Some(lon)) = (lat, lon) {
                let _ = state.db.console_set_geo(ip, country, city, lat, lon).await;
                let mut cache = state.geo_cache.lock().unwrap();
                cache.insert(
                    ip.to_owned(),
                    json!({"country": country, "city": city, "lat": lat, "lon": lon, "_t": now()}),
                );
            }
        }
    }
}

async fn api_stats(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let memory = in_memory_status(&state.pm).await;
    let total = state.db.count_peers().await.unwrap_or(0);
    let online = memory.values().filter(|e| is_online(**e)).count();
    let countries = state.db.console_distinct_countries().await.unwrap_or(0);
    Ok(Json(json!({
        "total": total,
        "online": online,
        "countries": countries,
        "uptime": now() - state.started_at,
        "version": crate::version::VERSION,
    })))
}

async fn api_events(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let events = state
        .db
        .console_get_events(200)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({"events": events})))
}

async fn api_server(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&state, &headers)?;
    let port: i32 = crate::common::get_arg_or("port", "21116".to_owned())
        .parse()
        .unwrap_or(21116);
    Ok(Json(json!({
        "rendezvous_port": port,
        "nat_port": port - 1,
        "ws_port": port + 2,
        "relay_port": port + 1,
        "console_port": crate::common::get_arg_or("CONSOLE_PORT", CONSOLE_PORT.to_string()),
        "public_key": server_public_key(),
        "uptime": now() - state.started_at,
    })))
}

fn server_public_key() -> String {
    // reuse the running server's key if available; hbbs keeps the secret key in RendezvousServer,
    // but the public key file sits next to the binary working dir.
    if let Ok(k) = std::fs::read_to_string("id_ed25519.pub") {
        return k.trim().to_owned();
    }
    "".to_owned()
}

async fn static_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = uri.path().trim_start_matches('/');
    let file = if path.is_empty() {
        CONSOLE_ASSETS.get_file("index.html")
    } else {
        CONSOLE_ASSETS.get_file(path).or_else(|| CONSOLE_ASSETS.get_file("index.html"))
    };
    match file {
        Some(f) => {
            let mime = match path.rsplit('.').next() {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "application/javascript",
                Some("css") => "text/css",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("ico") => "image/x-icon",
                _ => "application/octet-stream",
            };
            ([(axum::http::header::CONTENT_TYPE, mime)], f.contents()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
