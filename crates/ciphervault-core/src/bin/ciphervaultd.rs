//! Standalone CipherVault-X Desktop Server & CLI (`ciphervaultd`).
//!
//! Links directly against `ciphervault-core` and serves the CipherVault-X UI over
//! `http://127.0.0.1:<PORT>` alongside the JSON RPC API (`/api/rpc`) that mirrors the
//! Tauri 2 IPC commands one-for-one. Also pre-provisions a demo encrypted vault on first
//! launch with synthetic sample files so the application is immediately interactive.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ciphervault_core::{
    crypto::ffi::cleanse,
    encoding::{b64_decode_std, b64_encode_std},
    json::{escape_json_str, parse_flat_object},
    CloudAdapter, KdfParams, LocalMirrorAdapter, SyncEngine, Vault,
};

#[derive(Debug, Clone)]
struct VaultMeta {
    id: String,
    name: String,
    path: String,
    created_at: u64,
    mirror_path: Option<String>,
}

#[derive(Debug)]
struct DaemonState {
    metas: BTreeMap<String, VaultMeta>,
    unlocked: BTreeMap<String, Vault>,
    #[allow(dead_code)]
    auto_lock_minutes: u32,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn cleanse_string(s: String) {
    let mut b = s.into_bytes();
    cleanse(&mut b);
}

fn seed_demo_vault(base_dir: &Path) -> VaultMeta {
    let vault_dir = base_dir.join("Engineering-ZeroKnowledge-Vault");
    let mirror_dir = base_dir.join("CloudMirror-Simulation");
    let _ = fs::remove_dir_all(&vault_dir);
    let _ = fs::remove_dir_all(&mirror_dir);
    let _ = fs::create_dir_all(&mirror_dir);

    let v = Vault::create(&vault_dir, "CipherVault-Demo-2026!", KdfParams::INSECURE_TEST)
        .expect("failed to seed demo vault");
    v.create_dir_all("/Architecture/Specs").unwrap();
    v.create_dir_all("/Financials/Q4-Synthetic").unwrap();
    v.create_dir_all("/Incident-Response/Runbooks").unwrap();

    v.write_file(
        "/Architecture/Specs/cryptomator-format-8-notes.md",
        Cursor::new(
            b"# Cryptomator Format 8 Verification Notes (Synthetic)\n\n\
- Cipher Combo: `SIV_GCM`\n\
- Masterkey KDF: `scrypt` + RFC 3394 AES-256 Key Wrap\n\
- File Header: 68 bytes (12B nonce + AES-256-GCM encrypted 8B reserved + 32B content key + 16B tag)\n\
- File Chunks: 32 KiB payload + 12B nonce + 16B GCM tag, AAD = BE64(chunkIndex) || headerNonce\n\
- Filenames: RFC 5297 AES-256-SIV with parent dirId as AAD, URL-safe Base64 + `.c9r`\n"
                .to_vec(),
        ),
        true,
        None,
    )
    .unwrap();

    v.write_file(
        "/Financials/Q4-Synthetic/budget-projection-synthetic.csv",
        Cursor::new(
            b"department,quarter,allocated_usd,notes\n\
Applied Cryptography,2026-Q4,420000,External Cure53-style audit reserve (synthetic)\n\
Core Rust Engineering,2026-Q4,580000,Windows + Android + iOS core parity (synthetic)\n\
Zero-Knowledge Sync,2026-Q4,310000,Ciphertext-only adapter verification (synthetic)\n"
                .to_vec(),
        ),
        true,
        None,
    )
    .unwrap();

    v.write_file(
        "/Incident-Response/Runbooks/key-rotation-policy.txt",
        Cursor::new(
            b"SYNTHETIC RUNBOOK: Masterkey Passphrase Rotation\n\
1. Verify vault integrity via full AEAD tag scan (`check_integrity`).\n\
2. Rotate KEK passphrase (`change_password`), preserving masterkey.cryptomator.bkup.\n\
3. Sync updated masterkey.cryptomator to ciphertext mirror.\n"
                .to_vec(),
        ),
        true,
        None,
    )
    .unwrap();

    let id = v.config().jti.clone();
    VaultMeta {
        id,
        name: "Engineering Vault (Format 8)".to_string(),
        path: vault_dir.display().to_string(),
        created_at: now_secs(),
        mirror_path: Some(mirror_dir.display().to_string()),
    }
}

fn handle_rpc(state: &Mutex<DaemonState>, body: &[u8]) -> (u16, String) {
    let req = match parse_flat_object(body) {
        Ok(m) => m,
        Err(e) => return (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
    };
    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    let mut st = match state.lock() {
        Ok(g) => g,
        Err(_) => return (500, r#"{"ok":false,"error":"state lock poisoned"}"#.to_string()),
    };

    match cmd {
        "list_vaults" => {
            let mut items = Vec::new();
            for m in st.metas.values() {
                let unlocked = st.unlocked.contains_key(&m.id);
                let mirror = m
                    .mirror_path
                    .as_deref()
                    .map(escape_json_str)
                    .unwrap_or_else(|| "null".to_string());
                items.push(format!(
                    r#"{{"id":{},"name":{},"path":{},"unlocked":{},"createdAt":{},"mirrorPath":{}}}"#,
                    escape_json_str(&m.id),
                    escape_json_str(&m.name),
                    escape_json_str(&m.path),
                    unlocked,
                    m.created_at,
                    mirror
                ));
            }
            (200, format!(r#"{{"ok":true,"data":[{}]}}"#, items.join(",")))
        }
        "create_vault" => {
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("New Vault").to_string();
            let path = match req.get("path").and_then(|v| v.as_str()) {
                Some(p) if !p.trim().is_empty() => p.to_string(),
                _ => format!("/tmp/ciphervault-vaults/{}-{}", name.replace(' ', "-"), now_secs()),
            };
            let pw = req.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let params = KdfParams::INSECURE_TEST;
            let res = Vault::create(Path::new(&path), &pw, params);
            cleanse_string(pw);
            match res {
                Ok(v) => {
                    let id = v.config().jti.clone();
                    let meta = VaultMeta {
                        id: id.clone(),
                        name: name.clone(),
                        path: path.clone(),
                        created_at: now_secs(),
                        mirror_path: Some(format!("{path}-cloud-mirror")),
                    };
                    st.metas.insert(id.clone(), meta.clone());
                    st.unlocked.insert(id.clone(), v);
                    (
                        200,
                        format!(
                            r#"{{"ok":true,"data":{{"id":{},"name":{},"path":{},"unlocked":true,"createdAt":{},"mirrorPath":{}}}}}"#,
                            escape_json_str(&id),
                            escape_json_str(&name),
                            escape_json_str(&path),
                            meta.created_at,
                            escape_json_str(meta.mirror_path.as_deref().unwrap_or(""))
                        ),
                    )
                }
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "unlock_vault" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let pw = req.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let Some(meta) = st.metas.get(&id).cloned() else {
                return (404, r#"{"ok":false,"error":"vault not found"}"#.to_string());
            };
            let res = Vault::unlock(Path::new(&meta.path), &pw);
            cleanse_string(pw);
            match res {
                Ok(v) => {
                    st.unlocked.insert(id.clone(), v);
                    (
                        200,
                        format!(
                            r#"{{"ok":true,"data":{{"id":{},"name":{},"path":{},"unlocked":true,"createdAt":{}}}}}"#,
                            escape_json_str(&meta.id),
                            escape_json_str(&meta.name),
                            escape_json_str(&meta.path),
                            meta.created_at
                        ),
                    )
                }
                Err(e) => (401, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "lock_vault" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            st.unlocked.remove(id);
            (200, r#"{"ok":true,"data":null}"#.to_string())
        }
        "lock_all_vaults" => {
            st.unlocked.clear();
            (200, r#"{"ok":true,"data":null}"#.to_string())
        }
        "list_entries" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let vpath = req.get("vpath").and_then(|v| v.as_str()).unwrap_or("/");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.list(vpath) {
                Ok(entries) => (200, format!(r#"{{"ok":true,"data":[{}]}}"#, format_entries(&entries))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "create_folder" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let vpath = req.get("vpath").and_then(|v| v.as_str()).unwrap_or("");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.create_dir(vpath) {
                Ok(e) => (200, format!(r#"{{"ok":true,"data":{}}}"#, format_entry(&e))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "write_file_base64" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let vpath = req.get("vpath").and_then(|v| v.as_str()).unwrap_or("");
            let b64 = req.get("dataB64").and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match b64_decode_std(b64) {
                Ok(b) => b,
                Err(e) => return (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            };
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.write_file(vpath, Cursor::new(bytes), true, None) {
                Ok(e) => (200, format!(r#"{{"ok":true,"data":{}}}"#, format_entry(&e))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "read_preview_base64" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let vpath = req.get("vpath").and_then(|v| v.as_str()).unwrap_or("");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.read_to_vec(vpath, 2 * 1024 * 1024) {
                Ok(bytes) => (200, format!(r#"{{"ok":true,"data":{}}}"#, escape_json_str(&b64_encode_std(&bytes)))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "rename_entry" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let from = req.get("fromVpath").and_then(|v| v.as_str()).unwrap_or("");
            let to = req.get("toVpath").and_then(|v| v.as_str()).unwrap_or("");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.rename(from, to) {
                Ok(e) => (200, format!(r#"{{"ok":true,"data":{}}}"#, format_entry(&e))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "delete_entry" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let vpath = req.get("vpath").and_then(|v| v.as_str()).unwrap_or("");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.delete(vpath) {
                Ok(()) => (200, r#"{"ok":true,"data":null}"#.to_string()),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "search_vault" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let under = req.get("under").and_then(|v| v.as_str()).unwrap_or("/");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.search(query, under, 200) {
                Ok(entries) => (200, format!(r#"{{"ok":true,"data":[{}]}}"#, format_entries(&entries))),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "check_vault_integrity" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let Some(v) = st.unlocked.get(id) else {
                return (403, r#"{"ok":false,"error":"vault is locked"}"#.to_string());
            };
            match v.check_integrity() {
                Ok(rep) => {
                    let probs: Vec<String> = rep
                        .problems
                        .iter()
                        .map(|p| {
                            format!(
                                r#"{{"location":{},"error":{}}}"#,
                                escape_json_str(&p.location),
                                escape_json_str(&p.error)
                            )
                        })
                        .collect();
                    (
                        200,
                        format!(
                            r#"{{"ok":true,"data":{{"directories":{},"files":{},"bytesVerified":{},"problems":[{}]}}}}"#,
                            rep.directories,
                            rep.files,
                            rep.bytes_verified,
                            probs.join(",")
                        ),
                    )
                }
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "sync_vault_mirror" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mirror = req.get("mirrorPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let Some(meta) = st.metas.get_mut(&id) else {
                return (404, r#"{"ok":false,"error":"vault not found"}"#.to_string());
            };
            let target = if mirror.is_empty() {
                meta.mirror_path.clone().unwrap_or_else(|| format!("{}-mirror", meta.path))
            } else {
                meta.mirror_path = Some(mirror.clone());
                mirror
            };
            let root = PathBuf::from(&meta.path);
            let adapter = match LocalMirrorAdapter::new(PathBuf::from(&target)) {
                Ok(a) => a,
                Err(e) => return (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            };
            match SyncEngine::sync_bidirectional(&root, &adapter) {
                Ok(s) => (
                    200,
                    format!(
                        r#"{{"ok":true,"data":{{"provider":{},"uploaded":{},"downloaded":{},"unchanged":{},"bytesTransferred":{},"mirrorPath":{}}}}}"#,
                        escape_json_str(&s.provider),
                        s.uploaded,
                        s.downloaded,
                        s.unchanged,
                        s.bytes_transferred,
                        escape_json_str(&target)
                    ),
                ),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "change_password" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let old_pw = req.get("oldPassword").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let new_pw = req.get("newPassword").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let Some(meta) = st.metas.get(&id).cloned() else {
                return (404, r#"{"ok":false,"error":"vault not found"}"#.to_string());
            };
            let res = Vault::change_password(Path::new(&meta.path), &old_pw, &new_pw, KdfParams::INSECURE_TEST);
            cleanse_string(old_pw);
            cleanse_string(new_pw);
            match res {
                Ok(()) => (200, r#"{"ok":true,"data":null}"#.to_string()),
                Err(e) => (400, format!(r#"{{"ok":false,"error":{}}}"#, escape_json_str(&e.to_string()))),
            }
        }
        "inspect_ciphertext_tree" => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let Some(meta) = st.metas.get(id) else {
                return (404, r#"{"ok":false,"error":"vault not found"}"#.to_string());
            };
            let root = Path::new(&meta.path);
            let Ok(adapter) = LocalMirrorAdapter::new(root.to_path_buf()) else {
                return (400, r#"{"ok":false,"error":"cannot inspect root"}"#.to_string());
            };
            let objs = adapter.list_objects().unwrap_or_default();
            let list: Vec<String> = objs
                .iter()
                .map(|o| {
                    format!(
                        r#"{{"relPath":{},"size":{},"sha1":{}}}"#,
                        escape_json_str(&o.rel_path),
                        o.size,
                        escape_json_str(&o.sha1_hex)
                    )
                })
                .collect();
            (200, format!(r#"{{"ok":true,"data":[{}]}}"#, list.join(",")))
        }
        _ => (400, format!(r#"{{"ok":false,"error":"unknown command: {}"}}"#, cmd)),
    }
}

fn format_entry(e: &ciphervault_core::Entry) -> String {
    let sz = e.size.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string());
    let mtime = e.modified.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string());
    format!(
        r#"{{"name":{},"path":{},"kind":{},"size":{},"modified":{}}}"#,
        escape_json_str(&e.name),
        escape_json_str(&e.path),
        escape_json_str(e.kind.as_str()),
        sz,
        mtime
    )
}

fn format_entries(entries: &[ciphervault_core::Entry]) -> String {
    entries.iter().map(format_entry).collect::<Vec<_>>().join(",")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4173);
    let ui_html_path = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist/index.html"));

    let base_dir = std::env::temp_dir().join("ciphervault-x-live");
    let _ = fs::create_dir_all(&base_dir);
    let demo_meta = seed_demo_vault(&base_dir);
    let demo_vault = Vault::unlock(Path::new(&demo_meta.path), "CipherVault-Demo-2026!")
        .expect("failed to unlock seeded demo vault");

    let mut metas = BTreeMap::new();
    let mut unlocked = BTreeMap::new();
    unlocked.insert(demo_meta.id.clone(), demo_vault);
    metas.insert(demo_meta.id.clone(), demo_meta);

    let state = Arc::new(Mutex::new(DaemonState { metas, unlocked, auto_lock_minutes: 5 }));
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("failed to bind TCP listener");
    println!("CipherVault-X daemon listening on http://127.0.0.1:{port}");

    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        let ui_path = ui_html_path.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(&stream);
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).is_err() || req_line.is_empty() {
                return;
            }
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                return;
            }
            let (method, path) = (parts[0], parts[1]);
            let mut content_len: usize = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line == "\n" || line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; content_len];
            if content_len > 0 {
                let _ = reader.read_exact(&mut body);
            }

            let mut out = &stream;
            if method == "OPTIONS" {
                let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n";
                let _ = out.write_all(resp.as_bytes());
                return;
            }
            if method == "POST" && path == "/api/rpc" {
                let (status, json) = handle_rpc(&state, &body);
                let status_text = if status == 200 { "OK" } else { "Bad Request" };
                let header = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    json.len()
                );
                let _ = out.write_all(header.as_bytes());
                let _ = out.write_all(json.as_bytes());
                return;
            }
            // Serve the UI HTML
            let html = fs::read(&ui_path).unwrap_or_else(|_| b"<h1>CipherVault-X UI not found</h1>".to_vec());
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                html.len()
            );
            let _ = out.write_all(header.as_bytes());
            let _ = out.write_all(&html);
        });
    }
}
