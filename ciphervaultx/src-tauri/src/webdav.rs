//! Local loopback WebDAV virtual drive server (127.0.0.1 only) + Windows drive mounting.
//!
//! Security properties:
//! - Listens strictly on 127.0.0.1 (ephemeral port), never exposed to LAN.
//! - Protected by an unguessable per-mount random token prefix in the URL path.
//! - Zero plaintext is written to disk: all reads/writes stream through `cvz_core::Vault`.
//! - Automatically unmounted and shut down when the vault is locked or auto-locked.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cvz_core::{EntryKind, Vault, VaultEntry};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const MAX_PUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub vault_id: String,
    pub url: String,
    pub mount_point: String,
    pub drive_letter: Option<String>,
}

pub struct MountHandle {
    pub info: MountInfo,
    shutdown: Arc<AtomicBool>,
}

impl MountHandle {
    pub fn unmount(&mut self) {
        if let Some(letter) = self.info.drive_letter.take() {
            unmount_os_drive(&letter);
        }
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        self.unmount();
    }
}

pub async fn start_mount(
    vault_id: String,
    vault: Arc<RwLock<Vault>>,
) -> Result<MountHandle, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind loopback WebDAV server: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let url = format!("http://127.0.0.1:{port}/{token}/");

    let shutdown = Arc::new(AtomicBool::new(false));
    let srv_shutdown = shutdown.clone();
    let srv_token = token.clone();
    let srv_vault = vault.clone();

    tauri::async_runtime::spawn(async move {
        while !srv_shutdown.load(Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                Ok(Ok((stream, _addr))) => {
                    let conn_vault = srv_vault.clone();
                    let conn_token = srv_token.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = handle_connection(stream, conn_vault, conn_token).await;
                    });
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
    });

    let drive_letter = mount_os_drive(&url);
    let mount_point = drive_letter
        .as_ref()
        .map(|d| format!("{d}\\"))
        .unwrap_or_else(|| url.clone());

    Ok(MountHandle {
        info: MountInfo {
            vault_id,
            url,
            mount_point,
            drive_letter,
        },
        shutdown,
    })
}

async fn handle_connection(
    stream: TcpStream,
    vault: Arc<RwLock<Vault>>,
    token: String,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_uppercase();
    let raw_target = parts[1].to_string();

    let mut headers = HashMap::<String, String>::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut body = Vec::new();
    if content_len > 0 {
        if content_len > MAX_PUT_BYTES {
            let mut stream = reader.into_inner();
            write_response(&mut stream, "413 Payload Too Large", &[], &[]).await?;
            return Ok(());
        }
        body.resize(content_len, 0);
        reader.read_exact(&mut body).await?;
    }

    let mut stream = reader.into_inner();
    let prefix = format!("/{token}");
    let path_only = raw_target.split('?').next().unwrap_or(&raw_target);
    let Some(rel_raw) = path_only.strip_prefix(&prefix) else {
        write_response(&mut stream, "404 Not Found", &[], b"Not Found").await?;
        return Ok(());
    };
    let vault_path = decode_webdav_path(rel_raw);

    match method.as_str() {
        "OPTIONS" => {
            write_response(
                &mut stream,
                "200 OK",
                &[
                    ("DAV", "1, 2"),
                    ("MS-Author-Via", "DAV"),
                    (
                        "Allow",
                        "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, PROPFIND, LOCK, UNLOCK",
                    ),
                ],
                &[],
            )
            .await?;
        }
        "PROPFIND" => {
            let depth = headers
                .get("depth")
                .map(|s| s.as_str())
                .unwrap_or("1")
                .to_string();
            let v_clone = vault.clone();
            let vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                let target = guard.stat_entry(&vp).map_err(|e| e.to_string())?;
                let children = if depth != "0" && target.kind == EntryKind::Directory {
                    guard.list_dir(&vp).unwrap_or_default()
                } else {
                    Vec::new()
                };
                Ok::<(VaultEntry, Vec<VaultEntry>), String>((target, children))
            })
            .await;

            match res {
                Ok(Ok((target, children))) => {
                    let xml = build_propfind_xml(&prefix, &target, &children);
                    write_response(
                        &mut stream,
                        "207 Multi-Status",
                        &[("Content-Type", "application/xml; charset=utf-8")],
                        xml.as_bytes(),
                    )
                    .await?;
                }
                _ => {
                    write_response(&mut stream, "404 Not Found", &[], &[]).await?;
                }
            }
        }
        "GET" | "HEAD" => {
            let is_head = method == "HEAD";
            let v_clone = vault.clone();
            let vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                let stat = guard.stat_entry(&vp).map_err(|e| e.to_string())?;
                if stat.kind != EntryKind::File {
                    return Err("not a file".to_string());
                }
                if is_head {
                    return Ok((stat.size, Vec::new()));
                }
                let mut out = Vec::with_capacity(stat.size as usize);
                guard
                    .read_file_to_writer(&vp, &mut out)
                    .map_err(|e| e.to_string())?;
                Ok((out.len() as u64, out))
            })
            .await;

            match res {
                Ok(Ok((size, bytes))) => {
                    let len_str = size.to_string();
                    if is_head {
                        write_head_response(
                            &mut stream,
                            "200 OK",
                            &[
                                ("Content-Type", "application/octet-stream"),
                                ("Content-Length", &len_str),
                            ],
                        )
                        .await?;
                    } else {
                        write_response(
                            &mut stream,
                            "200 OK",
                            &[("Content-Type", "application/octet-stream")],
                            &bytes,
                        )
                        .await?;
                    }
                }
                _ => {
                    write_response(&mut stream, "404 Not Found", &[], &[]).await?;
                }
            }
        }
        "PUT" => {
            let v_clone = vault.clone();
            let vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                let mut cursor = Cursor::new(body);
                guard
                    .write_file_from_reader(&vp, &mut cursor)
                    .map_err(|e| e.to_string())
            })
            .await;

            match res {
                Ok(Ok(_)) => {
                    write_response(&mut stream, "201 Created", &[], &[]).await?;
                }
                _ => {
                    write_response(&mut stream, "409 Conflict", &[], &[]).await?;
                }
            }
        }
        "MKCOL" => {
            let v_clone = vault.clone();
            let vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                guard.create_dir(&vp).map_err(|e| e.to_string())
            })
            .await;

            match res {
                Ok(Ok(())) => {
                    write_response(&mut stream, "201 Created", &[], &[]).await?;
                }
                _ => {
                    write_response(&mut stream, "405 Method Not Allowed", &[], &[]).await?;
                }
            }
        }
        "DELETE" => {
            let v_clone = vault.clone();
            let vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                guard.delete_entry(&vp).map_err(|e| e.to_string())
            })
            .await;

            match res {
                Ok(Ok(())) => {
                    write_response(&mut stream, "204 No Content", &[], &[]).await?;
                }
                _ => {
                    write_response(&mut stream, "404 Not Found", &[], &[]).await?;
                }
            }
        }
        "MOVE" => {
            let dest_hdr = headers.get("destination").cloned().unwrap_or_default();
            let dest_path_raw = dest_hdr
                .find(&prefix)
                .map(|idx| &dest_hdr[idx + prefix.len()..])
                .unwrap_or("");
            let dst_vault_path = decode_webdav_path(dest_path_raw);
            let v_clone = vault.clone();
            let src_vp = vault_path.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                let guard = v_clone.read().map_err(|_| "lock poisoned".to_string())?;
                let (src_parent, src_name) = split_parent_name(&src_vp);
                let (dst_parent, dst_name) = split_parent_name(&dst_vault_path);
                if src_parent == dst_parent {
                    guard
                        .rename_entry(&src_vp, &dst_name)
                        .map_err(|e| e.to_string())
                } else {
                    guard
                        .move_entry(&src_vp, &dst_parent)
                        .map_err(|e| e.to_string())?;
                    let moved_path = if dst_parent == "/" {
                        format!("/{src_name}")
                    } else {
                        format!("{dst_parent}/{src_name}")
                    };
                    if src_name != dst_name {
                        guard
                            .rename_entry(&moved_path, &dst_name)
                            .map_err(|e| e.to_string())?;
                    }
                    Ok(())
                }
            })
            .await;

            match res {
                Ok(Ok(())) => {
                    write_response(&mut stream, "201 Created", &[], &[]).await?;
                }
                _ => {
                    write_response(&mut stream, "409 Conflict", &[], &[]).await?;
                }
            }
        }
        "LOCK" => {
            // Minimal WebDAV Class 2 lock response required by Windows Explorer WebClient.
            let lock_token = format!("urn:uuid:{}", uuid::Uuid::new_v4());
            let xml = format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>
<D:depth>infinity</D:depth><D:timeout>Second-3600</D:timeout>
<D:locktoken><D:href>{lock_token}</D:href></D:locktoken>
</D:activelock></D:lockdiscovery></D:prop>"#
            );
            let hdr_tok = format!("<{lock_token}>");
            write_response(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "application/xml; charset=utf-8"),
                    ("Lock-Token", &hdr_tok),
                ],
                xml.as_bytes(),
            )
            .await?;
        }
        "UNLOCK" => {
            write_response(&mut stream, "204 No Content", &[], &[]).await?;
        }
        _ => {
            write_response(&mut stream, "405 Method Not Allowed", &[], &[]).await?;
        }
    }

    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut resp = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("\r\n");
    stream.write_all(resp.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await
}

async fn write_head_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut resp = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("\r\n");
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

fn build_propfind_xml(prefix: &str, target: &VaultEntry, children: &[VaultEntry]) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#);
    append_entry_xml(&mut xml, prefix, target);
    for child in children {
        if child.kind != EntryKind::Unreadable {
            append_entry_xml(&mut xml, prefix, child);
        }
    }
    xml.push_str("</D:multistatus>");
    xml
}

fn append_entry_xml(xml: &mut String, prefix: &str, entry: &VaultEntry) {
    let encoded_path = encode_webdav_path(&entry.path);
    let href = if entry.kind == EntryKind::Directory {
        if encoded_path == "/" {
            format!("{prefix}/")
        } else {
            format!("{prefix}{encoded_path}/")
        }
    } else {
        format!("{prefix}{encoded_path}")
    };
    let display = xml_escape(if entry.name.is_empty() {
        "Vault"
    } else {
        &entry.name
    });
    xml.push_str("<D:response><D:href>");
    xml.push_str(&href);
    xml.push_str("</D:href><D:propstat><D:prop><D:displayname>");
    xml.push_str(&display);
    xml.push_str("</D:displayname>");
    if entry.kind == EntryKind::Directory {
        xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        xml.push_str("<D:resourcetype/><D:getcontentlength>");
        xml.push_str(&entry.size.to_string());
        xml.push_str("</D:getcontentlength>");
    }
    xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn encode_webdav_path(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        for b in seg.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
                out.push(*b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn decode_webdav_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    let s = String::from_utf8_lossy(&out).to_string();
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn split_parent_name(path: &str) -> (String, String) {
    let clean = path.trim_end_matches('/');
    match clean.rsplit_once('/') {
        Some(("", name)) => ("/".to_string(), name.to_string()),
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => ("/".to_string(), clean.to_string()),
    }
}

#[cfg(target_os = "windows")]
fn mount_os_drive(url: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("net")
        .args(["use", "*", url, "/persistent:no"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in stdout.split_whitespace() {
        let bytes = token.as_bytes();
        if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Some(token.to_ascii_uppercase());
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn mount_os_drive(_url: &str) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn unmount_os_drive(drive_letter: &str) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("net")
        .args(["use", drive_letter, "/delete", "/y"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(not(target_os = "windows"))]
fn unmount_os_drive(_drive_letter: &str) {}

pub fn reveal_mount_point(mount_point: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer.exe")
            .arg(mount_point)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(mount_point)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(mount_point)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = mount_point;
        Ok(())
    }
}
