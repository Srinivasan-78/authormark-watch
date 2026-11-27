use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_github_signature(
    payload: &[u8],
    signature_header: Option<&str>,
    secret: &str,
) -> bool {
    let Some(sig) = signature_header.and_then(|s| s.strip_prefix("sha256=")) else {
        return false;
    };
    if secret.is_empty() {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload);
    mac.verify_slice(&sig_bytes).is_ok()
}

pub fn run_webhook_server(port: u16, secret: &str) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Failed to bind {addr}: {e}"))?;
    println!("authormark-watch webhook listening on :{port}");

    for stream in listener.incoming().flatten() {
        let mut s = stream;
        let mut buf = [0u8; 65536];
        let Ok(n) = s.read(&mut buf) else { continue };
        if n == 0 {
            continue;
        }
        let req = String::from_utf8_lossy(&buf[..n]);
        let mut lines = req.split("\r\n");
        let request_line = lines.next().unwrap_or("");

        if request_line.starts_with("GET /health ") {
            let body = r#"{"ok":true,"service":"authormark-watch-webhook"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
            continue;
        }
        if !request_line.starts_with("POST /webhook ") {
            let body = r#"{"error":"Not found"}"#;
            let resp = format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = s.write_all(resp.as_bytes());
            continue;
        }

        let sig_hdr = req.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("x-hub-signature-256") {
                Some(v.trim())
            } else {
                None
            }
        });
        let body_bytes = req
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.as_bytes())
            .unwrap_or(&[]);

        if !secret.is_empty() && !verify_github_signature(body_bytes, sig_hdr, secret) {
            let body = r#"{"error":"Invalid signature"}"#;
            let resp = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = s.write_all(resp.as_bytes());
            continue;
        }

        let body = r#"{"accepted":true}"#;
        let resp = format!("HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        let _ = s.write_all(resp.as_bytes());
    }
    Ok(())
}
