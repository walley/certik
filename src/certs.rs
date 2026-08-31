//! Certificate / key loading and decoding.
//!
//! Reads PEM (multi-section) or DER files, identifies every section
//! (certificate, private key, public key, CSR) and renders a human
//! readable text report suitable for display in a TUI window.

use std::fmt::Write as _;
use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameRef, X509Req};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyze a certificate/key file and produce a full text report.
pub fn analyze_file(path: &Path) -> Result<String, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut report = String::new();
    let _ = writeln!(report, "File      : {}", path.display());
    let _ = writeln!(report, "Size      : {} bytes", raw.len());

    let text = String::from_utf8_lossy(&raw);
    if text.contains("-----BEGIN ") {
        let sections = split_pem(&raw);
        if sections.is_empty() {
            return Err("PEM markers found but no complete BEGIN/END blocks".into());
        }
        let _ = writeln!(report, "Format    : PEM, {} section(s)", sections.len());
        for (i, (label, block)) in sections.iter().enumerate() {
            let _ = writeln!(
                report,
                "\n=== Section {}: {} ({}) ===",
                i + 1,
                label,
                describe_label(label)
            );
            report.push_str(&analyze_block(label, block));
        }
    } else {
        let _ = writeln!(report, "Format    : DER");
        match analyze_der(&raw) {
            Some(fragment) => report.push_str(&fragment),
            None => return Err("not a recognized DER structure".into()),
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// PEM handling
// ---------------------------------------------------------------------------

/// Split a PEM file into `(label, raw block bytes)` pairs.
fn split_pem(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                current = Some((label.trim().to_string(), vec![line.to_string()]));
                continue;
            }
        }
        if let Some((label, lines)) = current.as_mut() {
            lines.push(line.to_string());
            let end_marker = format!("-----END {label}-----");
            if line.trim() == end_marker {
                out.push((label.clone(), lines.join("\n").into_bytes()));
                current = None;
            }
        }
    }
    out
}

fn describe_label(label: &str) -> &'static str {
    match label {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => "X.509 certificate",
        "PRIVATE KEY" => "private key (PKCS#8)",
        "ENCRYPTED PRIVATE KEY" => "encrypted private key (PKCS#8)",
        "RSA PRIVATE KEY" => "private key (PKCS#1 RSA)",
        "EC PRIVATE KEY" => "private key (SEC1 EC)",
        "PUBLIC KEY" => "public key (SPKI)",
        "RSA PUBLIC KEY" => "public key (PKCS#1 RSA)",
        "EC PUBLIC KEY" => "public key (EC point)",
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => "CSR (PKCS#10)",
        _ => "unrecognized",
    }
}

/// Decode one PEM section and return its report fragment.
fn analyze_block(label: &str, block: &[u8]) -> String {
    let mut out = String::new();
    match label {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => match X509::from_pem(block) {
            Ok(cert) => cert_report(&cert, &mut out),
            Err(e) => {
                let _ = writeln!(out, "  <decode failed: {e}>");
            }
        },
        "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
            match PKey::<Private>::private_key_from_pem(block) {
                Ok(key) => {
                    let encrypted = label == "ENCRYPTED PRIVATE KEY";
                    key_report(&key, label, encrypted, &mut out);
                }
                Err(e) => {
                    let _ = writeln!(out, "  <decode failed: {e}>");
                }
            }
        }
        "PUBLIC KEY" | "RSA PUBLIC KEY" | "EC PUBLIC KEY" => {
            match PKey::<Public>::public_key_from_pem(block) {
                Ok(key) => pubkey_report(&key, &mut out),
                Err(e) => {
                    let _ = writeln!(out, "  <decode failed: {e}>");
                }
            }
        }
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => match X509Req::from_pem(block) {
            Ok(req) => csr_report(&req, &mut out),
            Err(e) => {
                let _ = writeln!(out, "  <decode failed: {e}>");
            }
        },
        other => {
            let _ = writeln!(out, "  <no decoder for PEM label \"{other}\">");
        }
    }
    out
}

fn analyze_der(raw: &[u8]) -> Option<String> {
    let mut out = String::new();
    if let Ok(cert) = X509::from_der(raw) {
        let _ = writeln!(out, "\n=== DER: X.509 certificate ===");
        cert_report(&cert, &mut out);
        return Some(out);
    }
    if let Ok(key) = PKey::<Private>::private_key_from_der(raw) {
        let _ = writeln!(out, "\n=== DER: private key ===");
        key_report(&key, "DER", false, &mut out);
        return Some(out);
    }
    if let Ok(key) = PKey::<Public>::public_key_from_der(raw) {
        let _ = writeln!(out, "\n=== DER: public key ===");
        pubkey_report(&key, &mut out);
        return Some(out);
    }
    None
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

fn field(out: &mut String, name: &str, value: &str) {
    let _ = writeln!(out, "{:<11}: {}", name, value);
}

fn name_string(name: &X509NameRef) -> String {
    let parts: Vec<String> = name
        .entries()
        .map(|e| {
            let short = e.object().nid().short_name().unwrap_or("OID");
            let value = String::from_utf8_lossy(e.data().as_slice());
            format!("{short}={value}")
        })
        .collect();
    if parts.is_empty() {
        "<empty>".to_string()
    } else {
        parts.join(", ")
    }
}

fn algo_id_name(id: Id) -> &'static str {
    match id {
        Id::RSA => "RSA",
        Id::RSA_PSS => "RSA-PSS",
        Id::DSA => "DSA",
        Id::DH => "DH",
        Id::EC => "EC",
        Id::ED25519 => "Ed25519",
        Id::ED448 => "Ed448",
        Id::X25519 => "X25519",
        Id::X448 => "X448",
        _ => "unknown",
    }
}

fn key_summary(pkey_bits: u32, id: Id) -> String {
    format!("{}, {} bit", algo_id_name(id), pkey_bits)
}

/// Days from now until `asn1_time` (positive = in the future).
fn days_until(asn1_time_display: &str) -> Option<i64> {
    let trimmed = asn1_time_display.trim().trim_end_matches("GMT").trim();
    for fmt in ["%b %e %H:%M:%S %Y", "%b %d %H:%M:%S %Y"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            let now = chrono::Utc::now().naive_utc();
            return Some((t - now).num_days());
        }
    }
    None
}

fn cert_report(cert: &X509, out: &mut String) {
    field(out, "Subject", &name_string(cert.subject_name()));
    field(out, "Issuer", &name_string(cert.issuer_name()));

    let serial = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_dec_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "<?>".into());
    field(out, "Serial", &serial);

    let nb = cert.not_before().to_string();
    let na = cert.not_after().to_string();
    let _ = writeln!(out, "{:<11}: {}", "Not before", nb);
    match days_until(&na) {
        Some(days) => field(out, "Not after", &format!("{na}  ({days} day(s) remaining)")),
        None => field(out, "Not after", &na),
    }

    let sig = cert
        .signature_algorithm()
        .object()
        .nid()
        .long_name()
        .unwrap_or("unknown");
    field(out, "Sig algo", sig);

    match cert.public_key() {
        Ok(pk) => field(out, "Pub key", &key_summary(pk.bits(), pk.id())),
        Err(e) => field(out, "Pub key", &format!("<error: {e}>")),
    }

    if let Some(stack) = cert.subject_alt_names() {
        let mut list = Vec::new();
        for san in stack.iter() {
            if let Some(dns) = san.dnsname() {
                list.push(format!("DNS:{dns}"));
            } else if let Some(ip) = san.ipaddress() {
                list.push(format!("IP:{}", render_ip(ip)));
            } else if let Some(email) = san.email() {
                list.push(format!("email:{email}"));
            }
        }
        if !list.is_empty() {
            field(out, "SANs", &list.join(", "));
        }
    }

    // Typed extension getters (openssl 0.10 exposes no generic ext iterator).
    let mut ext_notes = Vec::new();
    if let Some(pathlen) = cert.pathlen() {
        ext_notes.push(format!("basicConstraints: CA, pathlen={pathlen}"));
    }
    if let Some(ski) = cert.subject_key_id() {
        ext_notes.push(format!("SKI: {}", hex_spaced(ski.as_slice())));
    }
    if let Some(aki) = cert.authority_key_id() {
        ext_notes.push(format!("AKI: {}", hex_spaced(aki.as_slice())));
    }
    if !ext_notes.is_empty() {
        field(out, "Extensions", &ext_notes.join("; "));
    }

    if let Ok(fp) = cert.digest(MessageDigest::sha256()) {
        field(out, "SHA-256", &hex_spaced(fp.as_ref()));
    }

    // Extra detail for RSA certificates.
    if let Ok(pk) = cert.public_key() {
        if let Ok(rsa) = pk.rsa() {
            rsa_details(&rsa, out);
        }
    }
}

fn key_report(pkey: &PKey<Private>, label: &str, encrypted: bool, out: &mut String) {
    let format = if label == "DER" {
        "DER".to_string()
    } else {
        describe_label(label).to_string()
    };
    field(
        out,
        "Format",
        &if encrypted {
            format!("{format} [ENCRYPTED]")
        } else {
            format
        },
    );
    field(out, "Algorithm", &key_summary(pkey.bits(), pkey.id()));

    if let Ok(rsa) = pkey.rsa() {
        rsa_details(&rsa, out);
    }

    if encrypted {
        let _ = writeln!(out, "           (content hidden - key is passphrase protected)");
        return;
    }
    if let Ok(der) = pkey.private_key_to_pkcs8() { if let Ok(digest) = openssl::hash::hash(MessageDigest::sha256(), &der) { field(out, "SHA-256*", &hex_spaced(&digest)) } }
    let _ = writeln!(out, "           (* over PKCS#8 DER encoding)");
}

fn pubkey_report(pkey: &PKey<Public>, out: &mut String) {
    field(out, "Algorithm", &key_summary(pkey.bits(), pkey.id()));
    if let Ok(der) = pkey.public_key_to_der() {
        if let Ok(digest) = openssl::hash::hash(MessageDigest::sha256(), &der) {
            field(out, "SHA-256", &hex_spaced(&digest));
        }
    }
}

fn rsa_details(rsa: &Rsa<impl openssl::pkey::HasPublic>, out: &mut String) {
    field(out, "RSA modulus", &format!("{} bit", rsa.n().num_bits()));
    let e = rsa.e();
    field(
        out,
        "RSA pub exp",
        &e.to_dec_str().map(|s| s.to_string()).unwrap_or_else(|_| "<?>".into()),
    );
}

fn csr_report(req: &X509Req, out: &mut String) {
    field(out, "Subject", &name_string(req.subject_name()));
    field(out, "Version", &req.version().to_string());
    match req.public_key() {
        Ok(pk) => field(out, "Pub key", &key_summary(pk.bits(), pk.id())),
        Err(e) => field(out, "Pub key", &format!("<error: {e}>")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_ip(ip: &[u8]) -> String {
    match ip.len() {
        4 => ip.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
        16 => ip
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => crate::api::hex(ip),
    }
}

fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// Certificate sets: leaf + intermediates + key
// ---------------------------------------------------------------------------

/// Which component a File > Open ... command targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSlot {
    Leaf,
    Intermediates,
    Key,
}

/// Material extracted from a file for a given slot.
#[derive(Debug)]
pub enum ExtractedMaterial {
    Certificate(X509),
    Certificates(Vec<X509>),
    PrivateKey(PKey<Private>),
}

/// Parse a file and pull out the material relevant for `slot`.
///
/// - Leaf slot      : first CERTIFICATE section
/// - Intermediates  : ALL certificate sections in the file
/// - Key slot       : first private key section
pub fn extract_material(path: &Path, slot: LoadSlot) -> Result<ExtractedMaterial, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut certs: Vec<X509> = Vec::new();
    let mut key: Option<PKey<Private>> = None;

    let text = String::from_utf8_lossy(&raw);
    if text.contains("-----BEGIN ") {
        for (label, block) in split_pem(&raw) {
            match label.as_str() {
                "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                    if let Ok(c) = X509::from_pem(&block) {
                        certs.push(c);
                    }
                }
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                    if key.is_none() {
                        if let Ok(k) = PKey::<Private>::private_key_from_pem(&block) {
                            key = Some(k);
                        }
                    }
                }
                _ => {}
            }
        }
    } else if let Ok(c) = X509::from_der(&raw) {
        certs.push(c);
    } else if let Ok(k) = PKey::<Private>::private_key_from_der(&raw) {
        key = Some(k);
    }

    match slot {
        LoadSlot::Leaf => certs
            .into_iter()
            .next()
            .map(ExtractedMaterial::Certificate)
            .ok_or_else(|| "no certificate found in this file".to_string()),
        LoadSlot::Intermediates => {
            if certs.is_empty() {
                Err("no certificates found in this file".into())
            } else {
                Ok(ExtractedMaterial::Certificates(certs))
            }
        }
        LoadSlot::Key => key
            .map(ExtractedMaterial::PrivateKey)
            .ok_or_else(|| "no private key found in this file".to_string()),
    }
}

/// A user-visible certificate set under assembly/verification.
pub struct CertSet {
    pub id: usize,
    pub title: String,
    pub leaf_path: Option<std::path::PathBuf>,
    pub leaf: Option<X509>,
    pub intermediates: Vec<(std::path::PathBuf, X509)>,
    pub key_path: Option<std::path::PathBuf>,
    pub key: Option<PKey<Private>>,
    /// Filled once all components are present and verification ran.
    pub verification: Option<String>,
    /// Bumped on every mutation so views can re-render lazily.
    pub version: u64,
}

impl CertSet {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            title: format!("Certificate Set #{id}"),
            leaf_path: None,
            leaf: None,
            intermediates: Vec::new(),
            key_path: None,
            key: None,
            verification: None,
            version: 0,
        }
    }

    fn touch(&mut self) {
        self.version += 1;
    }

    pub fn missing_components(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.leaf.is_none() {
            missing.push("certificate");
        }
        if self.key.is_none() {
            missing.push("key");
        }
        missing
    }

    pub fn is_complete(&self) -> bool {
        self.leaf.is_some() && self.key.is_some()
    }

    pub fn load_leaf(&mut self, path: &Path, cert: X509) {
        self.leaf_path = Some(path.to_path_buf());
        self.leaf = Some(cert);
        self.verification = None;
        self.touch();
    }

    pub fn load_intermediates(&mut self, path: &Path, certs: Vec<X509>) {
        for c in certs {
            self.intermediates.push((path.to_path_buf(), c));
        }
        self.verification = None;
        self.touch();
    }

    pub fn load_key(&mut self, path: &Path, key: PKey<Private>) {
        self.key_path = Some(path.to_path_buf());
        self.key = Some(key);
        self.verification = None;
        self.touch();
    }

    /// Full window text: status of every component + details + verification.
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let n_int = self.intermediates.len();

        // Header line
        lines.push(format!(
            "{}   [cert {}] [intermediate(s): {n_int}] [key {}]",
            self.title,
            if self.leaf.is_some() { "OK" } else { "--" },
            if self.key.is_some() { "OK" } else { "--" },
        ));
        lines.push("=".repeat(60));

        // Leaf
        match (&self.leaf, &self.leaf_path) {
            (Some(cert), Some(p)) => {
                lines.push(format!("LEAF CERTIFICATE  ({})", p.display()));
                push_indented(&mut lines, &render_certificate(cert));
            }
            _ => lines.push("LEAF CERTIFICATE  --  use File > Open Certificate...".into()),
        }

        // Intermediates
        if n_int == 0 {
            lines.push(
                "INTERMEDIATES     none loaded  --  use File > Open Intermediate... (optional)".into(),
            );
        } else {
            for (i, (p, cert)) in self.intermediates.iter().enumerate() {
                lines.push(format!("INTERMEDIATE #{}  ({})", i + 1, p.display()));
                push_indented(&mut lines, &render_certificate(cert));
            }
        }

        // Key
        match (&self.key, &self.key_path) {
            (Some(key), Some(p)) => {
                lines.push(format!("PRIVATE KEY  ({})", p.display()));
                push_indented(&mut lines, &render_private_key(key));
            }
            _ => lines.push("PRIVATE KEY       --  use File > Open Key...".into()),
        }

        // Verification section
        lines.push(String::new());
        lines.push("VERIFICATION".into());
        lines.push("-".repeat(60));
        if let Some(report) = &self.verification {
            push_indented(&mut lines, report);
        } else if self.is_complete() {
            push_indented(&mut lines, "pending...");
        } else {
            let missing = self.missing_components().join(", ");
            push_indented(
                &mut lines,
                &format!("waiting for remaining components: {missing}"),
            );
        }
        lines
    }
}

fn push_indented(lines: &mut Vec<String>, text: &str) {
    for l in text.lines() {
        if l.trim().is_empty() {
            lines.push(String::new());
        } else {
            lines.push(format!("  {l}"));
        }
    }
}

/// Render just the certificate detail block (no header).
pub(crate) fn render_certificate(cert: &X509) -> String {
    let mut out = String::new();
    cert_report(cert, &mut out);
    out
}

/// Render private key detail block (label-less; used inside sets).
pub(crate) fn render_private_key(key: &PKey<Private>) -> String {
    let mut out = String::new();
    key_report(key, "PKCS#8", false, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Export helpers for the API
// ---------------------------------------------------------------------------

/// Export the leaf certificate as PEM.
pub fn leaf_pem(set: &CertSet) -> Result<String, &'static str> {
    let cert = set.leaf.as_ref().ok_or("no certificate loaded")?;
    let pem = cert.to_pem().map_err(|_| "failed to encode certificate as PEM")?;
    String::from_utf8(pem).map_err(|_| "PEM output is not valid UTF-8")
}

/// Export the leaf certificate as human-readable text.
pub fn leaf_text(set: &CertSet) -> Result<String, &'static str> {
    let cert = set.leaf.as_ref().ok_or("no certificate loaded")?;
    Ok(render_certificate(cert))
}

/// Export intermediates as PEM (concatenated).
pub fn intermediates_pem(set: &CertSet) -> Result<String, &'static str> {
    if set.intermediates.is_empty() {
        return Err("no intermediate certificates loaded");
    }
    let mut out = Vec::new();
    for (_, cert) in &set.intermediates {
        let pem = cert.to_pem().map_err(|_| "failed to encode intermediate as PEM")?;
        out.extend_from_slice(&pem);
    }
    String::from_utf8(out).map_err(|_| "PEM output is not valid UTF-8")
}

/// Export intermediates as human-readable text.
pub fn intermediates_text(set: &CertSet) -> Result<String, &'static str> {
    if set.intermediates.is_empty() {
        return Err("no intermediate certificates loaded");
    }
    let mut out = String::new();
    for (i, (path, cert)) in set.intermediates.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(out, "Intermediate #{} ({})", i + 1, path.display());
        let _ = write!(out, "{}", render_certificate(cert));
    }
    Ok(out)
}

/// Export the private key as PEM.
pub fn key_pem(set: &CertSet) -> Result<String, &'static str> {
    let key = set.key.as_ref().ok_or("no private key loaded")?;
    let pem = key.private_key_to_pem_pkcs8().map_err(|_| "failed to encode key as PEM")?;
    String::from_utf8(pem).map_err(|_| "PEM output is not valid UTF-8")
}

/// Export the private key as human-readable text.
pub fn key_text(set: &CertSet) -> Result<String, &'static str> {
    let key = set.key.as_ref().ok_or("no private key loaded")?;
    Ok(render_private_key(key))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn is_self_signed(cert: &X509) -> bool {
    match cert.public_key() {
        Ok(pk) => cert.verify(&pk).unwrap_or(false),
        Err(_) => false,
    }
}

/// Try to verify the whole set:
///   1. build the chain from leaf through provided intermediates (signature checks)
///   2. check the private key matches the leaf's public key
///   3. check validity windows of every chain element
///
/// Returns a human readable report.
pub fn verify_set(set: &CertSet) -> Result<String, String> {
    let leaf = set
        .leaf
        .as_ref()
        .ok_or("cannot verify: no leaf certificate loaded")?;

    let mut out = String::new();
    let mut failures: Vec<String> = Vec::new();

    // --- 1. Chain building via signature verification ----------------------
    let mut chain: Vec<&X509> = vec![leaf];
    let mut used = vec![false; set.intermediates.len()];
    let mut sig_log: Vec<String> = Vec::new();
    let mut root_reached = is_self_signed(leaf);

    while !root_reached {
        let last = *chain.last().expect("chain never empty");
        let mut found: Option<usize> = None;
        for (i, (_, cand)) in set.intermediates.iter().enumerate() {
            if used[i] {
                continue;
            }
            let issuer_key = cand
                .public_key()
                .map_err(|e| format!("bad public key in intermediate #{i}: {e}"))?;
            match last.verify(&issuer_key) {
                Ok(true) => {
                    found = Some(i);
                    break;
                }
                Ok(false) => continue,
                Err(e) => sig_log.push(format!("error testing candidate #{i}: {e}")),
            }
        }
        match found {
            Some(i) => {
                let (_, cert) = &set.intermediates[i];
                used[i] = true;
                sig_log.push(format!(
                    "sig OK: [{}] signed by [{}]",
                    short_name_of(last),
                    short_name_of(cert)
                ));
                chain.push(cert);
                root_reached = is_self_signed(cert);
            }
            None => {
                sig_log.push(format!(
                    "no issuer found for [{}] among loaded intermediates",
                    short_name_of(last)
                ));
                break;
            }
        }
    }

    let depth = chain.len();
    field(&mut out, "Chain", &format!(
        "{} element(s): {}",
        depth,
        chain.iter().map(|c| short_name_of(c)).collect::<Vec<_>>().join(" -> ")
    ));
    if root_reached {
        let top = chain[depth - 1];
        let anchor = if depth == 1 && set.intermediates.is_empty() {
            "self-signed leaf"
        } else {
            "self-signed root"
        };
        field(&mut out, "Trust anchor", &format!("{anchor} [{}]", short_name_of(top)));
    } else {
        field(&mut out, "Trust anchor", "not provided (partial chain)");
    }
    for l in &sig_log {
        let _ = writeln!(out, "           {l}");
    }

    // --- 2. Key <-> certificate match --------------------------------------
    if let Some(key) = &set.key {
        let leaf_pub = leaf
            .public_key()
            .map_err(|e| format!("cannot get leaf public key: {e}"))?;
        let matches = leaf_pub.public_eq(key);
        field(
            &mut out,
            "Key match",
            if matches {
                "YES - private key matches certificate"
            } else {
                "NO - private key does NOT match certificate"
            },
        );
        if !matches {
            failures.push("private key does not match the certificate".into());
        }
    } else {
        field(&mut out, "Key match", "skipped (no key loaded)");
    }

    // --- 3. Validity of every chain element ---------------------------------
    let now_days_valid = |cert: &X509| -> Result<i64, String> {
        let nb = cert.not_before().to_string();
        let na = cert.not_after().to_string();
        let nb_days = days_until(&nb).ok_or("unparsable notBefore")?;
        let na_days = days_until(&na).ok_or("unparsable notAfter")?;
        if nb_days > 0 {
            return Err(format!("not yet valid ({nb_days}d until notBefore)"));
        }
        Ok(na_days)
    };
    let mut validity_notes = Vec::new();
    for cert in &chain {
        match now_days_valid(cert) {
            Ok(left) => validity_notes.push(format!("[{}] OK ({left}d left)", short_name_of(cert))),
            Err(e) => {
                validity_notes.push(format!("[{}] FAILED: {e}", short_name_of(cert)));
                failures.push(format!("validity: [{}] {e}", short_name_of(cert)));
            }
        }
    }
    field(&mut out, "Validity", &validity_notes.join(", "));

    // --- Overall ------------------------------------------------------------
    let overall = if failures.is_empty() {
        if root_reached {
            "PASS (full chain verified)".to_string()
        } else {
            "PARTIAL PASS (chain + key OK, but no trust anchor)".to_string()
        }
    } else {
        format!("FAIL ({})", failures.join("; "))
    };
    field(&mut out, "Overall", &overall);

    Ok(out)
}

fn short_name_of(cert: &X509) -> String {
    let name = name_string(cert.subject_name());
    if name.chars().count() > 32 {
        let cut: String = name.chars().take(29).collect();
        format!("{cut}...")
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_pair() -> (String, String) {
        crate::api::self_signed_pem_pair().unwrap()
    }

    #[test]
    fn decodes_self_signed_certificate() {
        let (cert_pem, _key) = sample_pair();
        let dir = std::env::temp_dir();
        let path = dir.join("certik_test_cert.pem");
        std::fs::write(&path, &cert_pem).unwrap();

        let report = analyze_file(&path).unwrap();
        assert!(report.contains("CERTIFICATE"));
        assert!(report.contains("Subject"), "missing subject line:\n{report}");
        assert!(report.contains("DNS:certik.local"), "missing SAN:\n{report}");
        assert!(report.contains("SHA-256"));
        assert!(report.contains("day(s) remaining"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decodes_private_keys() {
        let (_cert, key_pem) = sample_pair();
        let dir = std::env::temp_dir();
        let path = dir.join("certik_test_key.pem");
        std::fs::write(&path, &key_pem).unwrap();

        let report = analyze_file(&path).unwrap();
        assert!(report.contains("PKCS#8"), "missing PKCS#8:\n{report}");
        assert!(report.contains("Algorithm"));
        assert!(report.contains("SHA-256*"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn handles_combined_pem_files() {
        let (cert_pem, key_pem) = sample_pair();
        let combined = format!("{cert_pem}\n{key_pem}");
        let dir = std::env::temp_dir();
        let path = dir.join("certik_test_bundle.pem");
        std::fs::write(&path, combined).unwrap();

        let report = analyze_file(&path).unwrap();
        assert!(report.contains("2 section(s)"), "expected 2 sections:\n{report}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_garbage() {
        let dir = std::env::temp_dir();
        let path = dir.join("certik_test_garbage.pem");
        std::fs::write(&path, b"this is not a pem file").unwrap();
        assert!(analyze_file(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    // -- certificate set machinery ------------------------------------------

    /// Root CA -> intermediate -> leaf chain. Returns
    /// (ca_pem, intermediate_pem, leaf_pem, leaf_key_pem).
    fn ca_chain_materials() -> (String, String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "certik test root");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let int_key = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(vec![]).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params
            .distinguished_name
            .push(DnType::CommonName, "certik test intermediate");
        let int_issuer = Issuer::new(ca_params, ca_key);
        let int_cert = int_params.signed_by(&int_key, &int_issuer).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.test".into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "certik test leaf");
        let leaf_issuer = Issuer::new(int_params, int_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &leaf_issuer).unwrap();

        (
            ca_cert.pem(),
            int_cert.pem(),
            leaf_cert.pem(),
            leaf_key.serialize_pem(),
        )
    }

    /// Write text files into a fresh temp dir; returns the dir path.
    fn write_files(files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certik_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        dir
    }

    #[test]
    fn extracts_slots_from_files() {
        let (cert_pem, key_pem) = sample_pair();
        let dir = write_files(&[("cert.pem", &cert_pem), ("key.pem", &key_pem)]);

        let cert_path = dir.join("cert.pem");
        assert!(matches!(
            extract_material(&cert_path, LoadSlot::Leaf),
            Ok(ExtractedMaterial::Certificate(_))
        ));
        // Key slot on a cert-only file fails.
        assert!(extract_material(&cert_path, LoadSlot::Key).is_err());
        // Leaf slot on a key file fails.
        let key_path = dir.join("key.pem");
        assert!(extract_material(&key_path, LoadSlot::Leaf).is_err());
        assert!(matches!(
            extract_material(&key_path, LoadSlot::Key),
            Ok(ExtractedMaterial::PrivateKey(_))
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extracts_multiple_intermediates_from_bundle() {
        let (ca_pem, int_pem, _leaf_pem, _leaf_key_pem) = ca_chain_materials();
        let bundle = format!("{int_pem}{ca_pem}");
        let dir = write_files(&[("chain.pem", &bundle)]);

        match extract_material(&dir.join("chain.pem"), LoadSlot::Intermediates) {
            Ok(ExtractedMaterial::Certificates(certs)) => assert_eq!(certs.len(), 2),
            other => panic!("expected 2 certificates, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn incomplete_set_reports_missing() {
        let mut set = CertSet::new(1);
        let lines = set.render().join("\n");
        assert!(lines.contains("Open Certificate"));
        assert!(lines.contains("waiting for remaining components"));

        let (_, key_pem) = sample_pair();
        let key = PKey::<Private>::private_key_from_pem(key_pem.as_bytes()).unwrap();
        set.load_key(std::path::Path::new("/tmp/k.pem"), key);
        let lines = set.render().join("\n");
        assert!(lines.contains("certificate"), "still missing cert:\n{lines}");
    }

    #[test]
    fn verifies_self_signed_leaf_with_matching_key() {
        let (cert_pem, key_pem) = sample_pair();
        let cert = X509::from_pem(cert_pem.as_bytes()).unwrap();
        let key = PKey::<Private>::private_key_from_pem(key_pem.as_bytes()).unwrap();

        let mut set = CertSet::new(1);
        set.load_leaf(std::path::Path::new("/tmp/c.pem"), cert);
        set.load_key(std::path::Path::new("/tmp/k.pem"), key);

        let report = verify_set(&set).unwrap();
        assert!(report.contains("Key match"), "no key line:\n{report}");
        assert!(report.contains("YES"), "key should match:\n{report}");
        assert!(report.contains("PASS"), "should pass:\n{report}");
    }

    #[test]
    fn verifies_full_chain_with_intermediate() {
        let (ca_pem, int_pem, leaf_pem, leaf_key_pem) = ca_chain_materials();
        let bundle = format!("{int_pem}{ca_pem}");
        let dir = write_files(&[
            ("leaf.pem", &leaf_pem),
            ("chain.pem", &bundle),
            ("leaf.key", &leaf_key_pem),
        ]);

        let mut set = CertSet::new(3);
        match extract_material(&dir.join("leaf.pem"), LoadSlot::Leaf).unwrap() {
            ExtractedMaterial::Certificate(cert) => {
                set.load_leaf(&dir.join("leaf.pem"), cert)
            }
            other => panic!("expected certificate, got {other:?}"),
        }
        match extract_material(&dir.join("chain.pem"), LoadSlot::Intermediates).unwrap() {
            ExtractedMaterial::Certificates(certs) => {
                set.load_intermediates(&dir.join("chain.pem"), certs)
            }
            other => panic!("expected certificates, got {other:?}"),
        }
        match extract_material(&dir.join("leaf.key"), LoadSlot::Key).unwrap() {
            ExtractedMaterial::PrivateKey(key) => set.load_key(&dir.join("leaf.key"), key),
            other => panic!("expected private key, got {other:?}"),
        }

        assert!(set.is_complete());
        let report = verify_set(&set).unwrap();
        assert!(
            report.contains("3 element(s)"),
            "chain depth wrong:\n{report}"
        );
        assert!(report.contains("self-signed root"), "anchor:\n{report}");
        assert!(report.contains("PASS"), "overall:\n{report}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn partial_chain_without_root_is_partial_pass() {
        let (_ca_pem, int_pem, leaf_pem, leaf_key_pem) = ca_chain_materials();
        let dir = write_files(&[("leaf.pem", &leaf_pem), ("int.pem", &int_pem), ("leaf.key", &leaf_key_pem)]);

        let mut set = CertSet::new(4);
        if let ExtractedMaterial::Certificate(cert) =
            extract_material(&dir.join("leaf.pem"), LoadSlot::Leaf).unwrap()
        {
            set.load_leaf(&dir.join("leaf.pem"), cert);
        }
        if let ExtractedMaterial::Certificates(certs) =
            extract_material(&dir.join("int.pem"), LoadSlot::Intermediates).unwrap()
        {
            set.load_intermediates(&dir.join("int.pem"), certs);
        }
        if let ExtractedMaterial::PrivateKey(key) =
            extract_material(&dir.join("leaf.key"), LoadSlot::Key).unwrap()
        {
            set.load_key(&dir.join("leaf.key"), key);
        }

        let report = verify_set(&set).unwrap();
        assert!(
            report.contains("PARTIAL PASS"),
            "expected partial pass:\n{report}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_mismatched_key() {
        let (cert_pem, _) = sample_pair();
        let (_, other_key_pem) = sample_pair(); // independent pair
        let cert = X509::from_pem(cert_pem.as_bytes()).unwrap();
        let wrong_key = PKey::<Private>::private_key_from_pem(other_key_pem.as_bytes()).unwrap();

        let mut set = CertSet::new(2);
        set.load_leaf(std::path::Path::new("/tmp/c.pem"), cert);
        set.load_key(std::path::Path::new("/tmp/k.pem"), wrong_key);

        let report = verify_set(&set).unwrap();
        assert!(report.contains("NO"), "mismatch not detected:\n{report}");
        assert!(report.contains("FAIL"), "overall should fail:\n{report}");
    }
}
