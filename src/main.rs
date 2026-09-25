//! certik - HTTP(S) certificate handler/storage/manager/controller/deployer
//!
//! Runs as a local TUI application and optionally serves a management API
//! over HTTPS (see `api`).

mod api;
mod app;
mod certs;
mod snake;
mod tetris;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const USAGE: &str = "\
certik - certificate manager

USAGE:
    certik [OPTIONS]

OPTIONS:
    --api-bind <IP>       Address for the HTTPS API   (default: 0.0.0.0)
    --api-port <PORT>     Port for the HTTPS API     (default: 8443)
    --tls-cert <FILE>     PEM cert chain for the API server
    --tls-key  <FILE>     PEM private key for the API server
                          (if omitted, an ephemeral self-signed
                           certificate is generated at startup)
    --cert <FILE>         Load a PEM certificate into a new set at startup
    --key  <FILE>         Load a PEM private key into a new set at startup
    --no-api              Do not start the API server
    -h, --help            Show this help
";

#[derive(Debug, Clone)]
struct Cli {
    bind_ip: String,
    api_port: u16,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    no_api: bool,
    load_certs: Vec<PathBuf>,
    load_keys: Vec<PathBuf>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            bind_ip: "0.0.0.0".to_string(),
            api_port: 8443,
            tls_cert: None,
            tls_key: None,
            no_api: false,
            load_certs: Vec::new(),
            load_keys: Vec::new(),
        }
    }
}

fn parse_args() -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);

    fn next_value<T: std::str::FromStr>(it: &mut impl Iterator<Item = String>, name: &str) -> Result<T, String> {
        it.next()
            .ok_or_else(|| format!("missing value for {name}"))?
            .parse::<T>()
            .map_err(|_| format!("invalid value for {name}"))
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(USAGE.to_string()),
            "--no-api" => cli.no_api = true,
            "--api-bind" => cli.bind_ip = next_value(&mut args, "--api-bind")?,
            "--api-port" => cli.api_port = next_value(&mut args, "--api-port")?,
            "--tls-cert" => cli.tls_cert = Some(PathBuf::from(args.next().ok_or("missing value for --tls-cert")?)),
            "--tls-key" => cli.tls_key = Some(PathBuf::from(args.next().ok_or("missing value for --tls-key")?)),
            "--cert" => cli.load_certs.push(PathBuf::from(args.next().ok_or("missing value for --cert")?)),
            "--key" => cli.load_keys.push(PathBuf::from(args.next().ok_or("missing value for --key")?)),
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }
    Ok(cli)
}

fn main() {
    let cli = match parse_args() {
        Ok(c) => c,
        Err(msg) => {
            println!("{msg}");
            std::process::exit(if msg.starts_with("certik") { 0 } else { 2 });
        }
    };

    let log: api::SharedLog = Arc::new(Mutex::new(Vec::new()));
    let sets: api::SharedSets = Arc::new(Mutex::new(Vec::new()));
    let focus: api::SharedFocus = Arc::new(std::sync::atomic::AtomicUsize::new(api::NO_FOCUS));

    // Keep the runtime alive until the TUI exits.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start tokio runtime");

    if !cli.no_api {
        let bind: SocketAddr = format!("{}:{}", cli.bind_ip, cli.api_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], cli.api_port)));
        let cfg = api::ApiConfig {
            bind,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
        };
        api::log_line(&log, format!("API subsystem starting on https://{bind} ..."));
        let log2 = log.clone();
        let sets2 = sets.clone();
        let focus2 = focus.clone();
        rt.spawn(async move {
            let result = api::run(cfg, log2.clone(), sets2, focus2).await;
            if let Err(e) = result {
                let msg = format!("API ERROR: {e}");
                eprintln!("{msg}");
                api::log_line(&log2, msg);
            }
        });
    } else {
        api::log_line(&log, "API subsystem disabled (--no-api)".to_string());
    }

    if let Err(e) = app::run(log, sets, focus, &cli.load_certs, &cli.load_keys) {
        eprintln!("certik: {e}");
        std::process::exit(1);
    }

    drop(rt);
}
