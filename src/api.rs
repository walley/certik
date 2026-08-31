//! HTTPS API subsystem.
//!
//! Serves the certik management API over TLS. Endpoints are kept in a small
//! pure routing function (`route`) so they are trivially testable; `run`
//! wires that function into a hyper 1.x server behind tokio-rustls.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Log shared between the API server task and the TUI (server window).
pub type SharedLog = Arc<Mutex<Vec<String>>>;

/// Certificate sets shared between the TUI and API server.
pub type SharedSets = Arc<Mutex<Vec<Arc<Mutex<crate::certs::CertSet>>>>>;

/// Id of the currently focused (topmost) certificate-set window, shared between
/// the TUI and the API server so the API serves data only from the focused set.
/// `NO_FOCUS` means no set is focused (the API then serves 404).
pub type SharedFocus = Arc<AtomicUsize>;

pub const NO_FOCUS: usize = usize::MAX;

const MAX_LOG_LINES: usize = 500;

pub fn log_line(log: &SharedLog, line: String) {
    if let Ok(mut buf) = log.lock() {
        buf.push(line);
        let len = buf.len();
        if len > MAX_LOG_LINES {
            buf.drain(0..len - MAX_LOG_LINES);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Parse the `?format=` query parameter. Defaults to `"pem"`.
fn parse_format(uri: &str) -> &str {
    if let Some(q) = uri.find('?') {
        for param in uri[q + 1..].split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "format" {
                    return v;
                }
            }
        }
    }
    "pem"
}

/// Pure routing core for stateless endpoints.
pub fn route(method: &str, path: &str) -> (u16, &'static str) {
    match path {
        "/ping" => match method {
            "GET" | "HEAD" => (200, "pong"),
            _ => (405, "method not allowed"),
        },
        _ => (404, "not found"),
    }
}

fn response(status: u16, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response is valid")
}

fn response_owned(status: u16, body: String, ct: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", ct)
        .body(Full::new(Bytes::from(body)))
        .expect("response is valid")
}

/// Resolve the set that the API should serve from: the currently focused one,
/// identified by the shared `focus` id. Returns `None` when no set is focused.
fn focused_set(
    sets: &SharedSets,
    focus: &SharedFocus,
) -> Option<Arc<Mutex<crate::certs::CertSet>>> {
    let id = focus.load(Ordering::SeqCst);
    if id == NO_FOCUS {
        return None;
    }
    let sets = sets.lock().ok()?;
    sets.iter().find(|s| matches!(s.lock(), Ok(st) if st.id == id)).cloned()
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    log: SharedLog,
    sets: SharedSets,
    focus: SharedFocus,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().as_str();
    let uri = req.uri().to_string();
    let path = req.uri().path();
    let fmt = parse_format(&uri);

    // Try stateless route first.
    let (status, text) = route(method, path);
    if status != 404 {
        log_line(&log, format!("{method} {path} from {peer} -> {status}"));
        return Ok(response(status, text));
    }

    // Stateful endpoints — only GET/HEAD allowed.
    if method != "GET" && method != "HEAD" {
        log_line(&log, format!("{method} {path} from {peer} -> 405"));
        return Ok(response(405, "method not allowed"));
    }

    // Serve only from the currently focused certificate-set window.
    let Some(set) = focused_set(&sets, &focus) else {
        log_line(&log, format!("{method} {path} from {peer} -> 404 (no focused set)"));
        return Ok(response(404, "no focused certificate set"));
    };

    let lock = match set.lock() {
        Ok(l) => l,
        Err(_) => {
            return Ok(response(500, "internal error"));
        }
    };

    let (status, body, ct) = match path {
        "/certificate" => match fmt {
            "text" => match crate::certs::leaf_text(&lock) {
                Ok(t) => (200, t, "text/plain; charset=utf-8"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
            _ => match crate::certs::leaf_pem(&lock) {
                Ok(p) => (200, p, "application/x-pem-file"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
        },
        "/intermediate" => match fmt {
            "text" => match crate::certs::intermediates_text(&lock) {
                Ok(t) => (200, t, "text/plain; charset=utf-8"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
            _ => match crate::certs::intermediates_pem(&lock) {
                Ok(p) => (200, p, "application/x-pem-file"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
        },
        "/key" => match fmt {
            "text" => match crate::certs::key_text(&lock) {
                Ok(t) => (200, t, "text/plain; charset=utf-8"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
            _ => match crate::certs::key_pem(&lock) {
                Ok(p) => (200, p, "application/x-pem-file"),
                Err(e) => (404, e.to_string(), "text/plain; charset=utf-8"),
            },
        },
        _ => (404, "not found".to_string(), "text/plain; charset=utf-8"),
    };

    drop(lock);
    log_line(&log, format!("{method} {path}?format={fmt} from {peer} -> {status}"));
    Ok(response_owned(status, body, ct))
}

// ---------------------------------------------------------------------------
// TLS material
// ---------------------------------------------------------------------------

/// Generate an ephemeral self-signed certificate for dev mode.
/// Returns (cert_pem, key_pem).
pub fn self_signed_pem_pair() -> Result<(String, String), String> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "certik.local".into()])
        .map_err(|e| format!("rcgen: {e}"))?;
    Ok((ck.cert.pem(), ck.signing_key.serialize_pem()))
}

fn load_tls_material(cert_path: &Path, key_path: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| format!("reading {}: {e}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path).map_err(|e| format!("reading {}: {e}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| format!("bad certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path.display()));
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("bad private key PEM: {e}"))?
        .ok_or_else(|| format!("no private key found in {}", key_path.display()))?;

    Ok((certs, key))
}

fn self_signed_der() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String), String> {
    let (cert_pem, key_pem) = self_signed_pem_pair()?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("internal: generated cert unparsable: {e}"))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("internal: generated key unparsable: {e}"))?
        .ok_or("internal: generated key missing")?;
    Ok((certs, key, cert_pem))
}

async fn build_acceptor(cfg: &ApiConfig, log: &SharedLog) -> Result<TlsAcceptor, String> {
    let (certs, key) = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => {
            let material = load_tls_material(c, k)?;
            log_line(log, format!("TLS: using {} + {}", c.display(), k.display()));
            material
        }
        (None, None) => {
            let (certs, key, cert_pem) = self_signed_der()?;
            // Surface the serving identity in the server window.
            if let Ok(parsed) = openssl::x509::X509::from_pem(cert_pem.as_bytes()) {
                if let Ok(fp) = parsed.digest(openssl::hash::MessageDigest::sha256()) {
                    log_line(log, format!("TLS: ephemeral self-signed cert, sha256={}", hex(&fp)));
                } else {
                    log_line(log, "TLS: ephemeral self-signed cert".into());
                }
            }
            log_line(log, "TLS: clients must skip verification (curl -k)".into());
            (certs, key)
        }
        _ => {
            return Err("--tls-cert and --tls-key must be given together".into());
        }
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config: {e}"))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Server loop
// ---------------------------------------------------------------------------

pub async fn run(cfg: ApiConfig, log: SharedLog, sets: SharedSets, focus: SharedFocus) -> std::io::Result<()> {
    let acceptor = match build_acceptor(&cfg, &log).await {
        Ok(a) => a,
        Err(e) => {
            log_line(&log, format!("API ERROR: {e}"));
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e));
        }
    };

    let listener = TcpListener::bind(cfg.bind).await?;
    log_line(&log, format!("API listening on https://{}", cfg.bind));
    log_line(&log, "GET /ping -> pong".into());
    log_line(&log, "GET /certificate -> leaf cert (pem)".into());
    log_line(&log, "GET /certificate?format=text -> leaf cert (text)".into());
    log_line(&log, "GET /intermediate -> intermediate certs (pem)".into());
    log_line(&log, "GET /key -> private key (pem)".into());
    log_line(&log, "serves the currently focused certificate set".into());

    serve(listener, acceptor, log, sets, focus).await
}

async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    log: SharedLog,
    sets: SharedSets,
    focus: SharedFocus,
) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let log = log.clone();
        let sets = sets.clone();
        let focus = focus.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    let service =
                        service_fn(move |req| handle(req, peer, log.clone(), sets.clone(), focus.clone()));
                    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection_with_upgrades(TokioIo::new(tls), service).await;
                }
                Err(e) => {
                    log_line(&log, format!("TLS handshake failed from {peer}: {e}"));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pongs() {
        assert_eq!(route("GET", "/ping"), (200, "pong"));
    }

    #[test]
    fn unknown_paths_404() {
        assert_eq!(route("GET", "/nope"), (404, "not found"));
    }

    #[test]
    fn post_ping_not_allowed() {
        assert_eq!(route("POST", "/ping"), (405, "method not allowed"));
    }

    #[test]
    fn focus_selects_only_the_focused_set() {
        let sets: SharedSets = Arc::new(Mutex::new(Vec::new()));
        let focus: SharedFocus = Arc::new(AtomicUsize::new(NO_FOCUS));
        let set1 = Arc::new(Mutex::new(crate::certs::CertSet::new(1)));
        let set2 = Arc::new(Mutex::new(crate::certs::CertSet::new(2)));
        {
            let mut s = sets.lock().unwrap();
            s.push(Arc::clone(&set1));
            s.push(Arc::clone(&set2));
        }

        // No focused set -> nothing is served.
        assert!(focused_set(&sets, &focus).is_none());

        // Focus set 2 -> only set 2 is resolved, even though set 1 exists.
        focus.store(2, Ordering::SeqCst);
        let resolved = focused_set(&sets, &focus).expect("focused set");
        assert_eq!(resolved.lock().unwrap().id, 2);

        // Focus an id that doesn't exist -> nothing served.
        focus.store(999, Ordering::SeqCst);
        assert!(focused_set(&sets, &focus).is_none());
    }

    /// End-to-end: TLS from PEM files + GET /ping over a real socket.
    #[tokio::test]
    async fn ping_over_real_tls() {
        let dir = std::env::temp_dir();
        let cert_path = dir.join("certik_test_api_cert.pem");
        let key_path = dir.join("certik_test_api_key.pem");
        let (cert_pem, key_pem) = self_signed_pem_pair().unwrap();
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cfg = ApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert: Some(cert_path.clone()),
            tls_key: Some(key_path.clone()),
        };
        let log: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let sets: SharedSets = Arc::new(Mutex::new(Vec::new()));
        let focus: SharedFocus = Arc::new(AtomicUsize::new(NO_FOCUS));
        let acceptor = build_acceptor(&cfg, &log).await.expect("acceptor");
        let listener = TcpListener::bind(cfg.bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, acceptor, log, sets, focus));

        // Client trusts the server's certificate directly.
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), tcp)
            .await
            .expect("TLS handshake");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = String::new();
        tls.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.ends_with("pong"), "got: {response}");

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }

    #[test]
    fn self_signed_material_is_usable_by_rustls() {
        let (cert_pem, key_pem) = self_signed_pem_pair().unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!certs.is_empty());

        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .unwrap()
            .expect("key present");

        // Full rustls config must build from the generated material.
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let parsed = openssl::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();
        let values: Vec<String> = parsed
            .subject_name()
            .entries()
            .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned())
            .collect();
        assert!(
            values.iter().any(|v| v.contains("rcgen")),
            "unexpected subject values: {values:?}"
        );
    }

    #[test]
    fn parse_format_defaults_to_pem() {
        assert_eq!(parse_format("/certificate"), "pem");
        assert_eq!(parse_format("/certificate?format=text"), "text");
        assert_eq!(parse_format("/certificate?foo=bar&format=pem"), "pem");
        assert_eq!(parse_format("/certificate?format=der"), "der");
    }

    #[test]
    fn static_routes_work() {
        assert_eq!(route("GET", "/ping"), (200, "pong"));
        assert_eq!(route("GET", "/certificate"), (404, "not found"));
    }

    /// End-to-end: load cert+key, start API, hit all data endpoints.
    #[tokio::test]
    async fn data_endpoints_over_tls() {
        let dir = std::env::temp_dir();
        let cert_path = dir.join("certik_test_api_data_cert.pem");
        let key_path = dir.join("certik_test_api_data_key.pem");
        let (cert_pem, key_pem) = self_signed_pem_pair().unwrap();
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cfg = ApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert: Some(cert_path.clone()),
            tls_key: Some(key_path.clone()),
        };
        let log: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let sets: SharedSets = Arc::new(Mutex::new(Vec::new()));
        let focus: SharedFocus = Arc::new(AtomicUsize::new(NO_FOCUS));

        // Load a certificate set.
        let parsed_cert = openssl::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();
        let parsed_key = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
        let mut set = crate::certs::CertSet::new(1);
        set.load_leaf(std::path::Path::new("/tmp/test.pem"), parsed_cert);
        set.load_key(std::path::Path::new("/tmp/test.key"), parsed_key);
        {
            let mut s = sets.lock().unwrap();
            s.push(Arc::new(Mutex::new(set)));
        }
        // Focus the loaded set so the data endpoints serve it.
        focus.store(1, Ordering::SeqCst);

        let acceptor = build_acceptor(&cfg, &log).await.expect("acceptor");
        let listener = TcpListener::bind(cfg.bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, acceptor, log, sets, focus));

        // Build TLS client.
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn get(connector: &tokio_rustls::TlsConnector, addr: std::net::SocketAddr, path: &str) -> String {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
            let mut tls = connector.connect(server_name, tcp).await.unwrap();
            let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut resp = String::new();
            tls.read_to_string(&mut resp).await.unwrap();
            resp
        }

        // GET /certificate (PEM)
        let r = get(&connector, addr, "/certificate").await;
        assert!(r.contains("200"), "GET /certificate: {r}");
        assert!(r.contains("BEGIN CERTIFICATE"), "expected PEM cert");

        // GET /certificate?format=text
        let r = get(&connector, addr, "/certificate?format=text").await;
        assert!(r.contains("200"), "GET /certificate?format=text: {r}");
        assert!(r.contains("Subject"), "expected text output");

        // GET /key (PEM)
        let r = get(&connector, addr, "/key").await;
        assert!(r.contains("200"), "GET /key: {r}");
        assert!(r.contains("BEGIN PRIVATE KEY"), "expected PEM key");

        // GET /key?format=text
        let r = get(&connector, addr, "/key?format=text").await;
        assert!(r.contains("200"), "GET /key?format=text: {r}");
        assert!(r.contains("Algorithm") || r.contains("RSA") || r.contains("EC"), "expected key text");

        // GET /intermediate (should be 404 - none loaded)
        let r = get(&connector, addr, "/intermediate").await;
        assert!(r.contains("404"), "GET /intermediate should be 404: {r}");

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }
}
