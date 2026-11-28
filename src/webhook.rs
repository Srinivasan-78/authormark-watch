use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;

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

fn read_http_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>), &'static str> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    let header_end = loop {
        let n = stream.read(&mut chunk).map_err(|_| "read error")?;
        if n == 0 {
            return Err("unexpected EOF");
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if raw.len() > MAX_HEADER_BYTES {
            return Err("headers too large");
        }
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let content_length = header_str
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    if content_length > MAX_BODY_BYTES {
        return Err("payload too large");
    }

    let body_start = header_end + 4;
    while raw.len() - body_start < content_length {
        let n = stream.read(&mut chunk).map_err(|_| "read error")?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() - body_start > MAX_BODY_BYTES {
            return Err("payload too large");
        }
    }

    let end = (body_start + content_length).min(raw.len());
    Ok((header_str, raw[body_start..end].to_vec()))
}

fn send_json(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

pub fn run_webhook_server(port: u16, secret: &str) -> Result<(), String> {
    if secret.trim().is_empty() {
        return Err("WEBHOOK_SECRET must be non-empty before starting webhook server".into());
    }
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Failed to bind {addr}: {e}"))?;
    println!("authormark-watch webhook listening on :{port}");

    for mut stream in listener.incoming().flatten() {
        let Ok((headers, body_bytes)) = read_http_request(&mut stream) else {
            send_json(
                &mut stream,
                "400 Bad Request",
                r#"{"error":"Malformed request"}"#,
            );
            continue;
        };

        let request_line = headers.lines().next().unwrap_or("");
        if request_line.starts_with("GET /health ") {
            send_json(
                &mut stream,
                "200 OK",
                r#"{"ok":true,"service":"authormark-watch-webhook"}"#,
            );
            continue;
        }
        if !request_line.starts_with("POST /webhook ") {
            send_json(&mut stream, "404 Not Found", r#"{"error":"Not found"}"#);
            continue;
        }

        let sig_hdr = headers.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("x-hub-signature-256") {
                Some(v.trim())
            } else {
                None
            }
        });

        if !verify_github_signature(&body_bytes, sig_hdr, secret) {
            send_json(
                &mut stream,
                "401 Unauthorized",
                r#"{"error":"Invalid signature"}"#,
            );
            continue;
        }

        send_json(&mut stream, "202 Accepted", r#"{"accepted":true}"#);
    }
    Ok(())
}
