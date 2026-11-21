use std::fs;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use aes_kw::KekAes256;
use aes_siv::siv::Aes256Siv;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use cvz_core::cryptomator::CryptomatorVault;
use cvz_core::standalone::{decrypt_standalone_file, encrypt_standalone_file};
use cvz_core::{Argon2Params, CipherSuite, EntryKind, VaultError};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params as ScryptParams};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use tempfile::tempdir;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn standalone_zip_file_encrypt_decrypt_and_tamper() {
    let dir = tempdir().expect("tempdir");
    let src = dir.path().join("archive.zip");
    let enc = dir.path().join("archive.zip.cvxenc");
    let out = dir.path().join("archive_restored.zip");

    let payload: Vec<u8> = (0..150_000usize).map(|i| ((i * 13) & 0xff) as u8).collect();
    fs::write(&src, &payload).expect("write zip");

    let pw = "standalone-archive-passphrase-2026!";
    let kdf = Argon2Params {
        m_cost: 65_536,
        t_cost: 2,
        p_cost: 1,
    };

    let n = encrypt_standalone_file(&src, &enc, pw, CipherSuite::XChaCha20Poly1305, kdf)
        .expect("encrypt standalone");
    assert_eq!(n, payload.len() as u64);

    // Wrong password rejected and leaves no output file.
    let bad_out = dir.path().join("bad_out.zip");
    assert!(matches!(
        decrypt_standalone_file(&enc, &bad_out, "wrong-password-123456"),
        Err(VaultError::InvalidCredentials)
    ));
    assert!(!bad_out.exists());

    // Valid decrypt matches byte-for-byte.
    let m = decrypt_standalone_file(&enc, &out, pw).expect("decrypt standalone");
    assert_eq!(m, payload.len() as u64);
    assert_eq!(fs::read(&out).expect("read out"), payload);

    // Tamper 1 byte -> fails with Integrity.
    let mut tampered = fs::read(&enc).expect("read enc");
    tampered[200] ^= 0x01;
    fs::write(&enc, &tampered).expect("write tampered");
    let tamper_out = dir.path().join("tamper_out.zip");
    assert!(matches!(
        decrypt_standalone_file(&enc, &tamper_out, pw),
        Err(VaultError::Integrity)
    ));
    assert!(!tamper_out.exists());
}

#[test]
fn cryptomator_format8_siv_gcm_interop_open_list_and_export() {
    // Construct a spec-compliant Cryptomator Vault Format 8 (SIV_GCM) vault on disk
    // and verify that CryptomatorVault opens, lists, and decrypts files accurately.
    let dir = tempdir().expect("tempdir");
    let cm_root = dir.path().join("cm_vault");
    fs::create_dir_all(&cm_root).expect("mkdir");

    let password = "cryptomator-interop-passphrase";
    let salt = [0x11u8; 8];
    let enc_key = [0x22u8; 32];
    let mac_key = [0x33u8; 32];

    let mut kek_bytes = [0u8; 32];
    let params = ScryptParams::new(14, 8, 1, 32).expect("scrypt params"); // N = 16384
    scrypt(password.as_bytes(), &salt, &params, &mut kek_bytes).expect("scrypt");
    let kek = KekAes256::from(kek_bytes);

    let mut wrapped_enc = [0u8; 40];
    let mut wrapped_mac = [0u8; 40];
    kek.wrap(&enc_key, &mut wrapped_enc).expect("wrap enc");
    kek.wrap(&mac_key, &mut wrapped_mac).expect("wrap mac");

    let version: u32 = 999;
    let mut vmac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("hmac");
    vmac.update(&version.to_be_bytes());
    let version_mac = vmac.finalize().into_bytes();

    let mk_json = format!(
        r#"{{"version":999,"scryptSalt":"{}","scryptCostParam":16384,"scryptBlockSize":8,"primaryMasterKey":"{}","hmacMasterKey":"{}","versionMac":"{}"}}"#,
        STANDARD.encode(salt),
        STANDARD.encode(wrapped_enc),
        STANDARD.encode(wrapped_mac),
        STANDARD.encode(version_mac),
    );
    fs::write(cm_root.join("masterkey.cryptomator"), mk_json).expect("write mk");

    // Create vault.cryptomator JWT (HS256 signed with enc_key || mac_key)
    let hdr_b64 = URL_SAFE_NO_PAD
        .encode(r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"HS256"}"#);
    let pay_b64 = URL_SAFE_NO_PAD.encode(
        r#"{"jti":"test-vault-8","format":8,"cipherCombo":"SIV_GCM","shorteningThreshold":220}"#,
    );
    let signing = format!("{hdr_b64}.{pay_b64}");
    let mut jwt_key = [0u8; 64];
    jwt_key[0..32].copy_from_slice(&enc_key);
    jwt_key[32..64].copy_from_slice(&mac_key);
    let mut jmac = <HmacSha256 as Mac>::new_from_slice(&jwt_key).expect("jwt hmac");
    jmac.update(signing.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(jmac.finalize().into_bytes());
    fs::write(
        cm_root.join("vault.cryptomator"),
        format!("{signing}.{sig_b64}"),
    )
    .expect("write jwt");

    // Compute root dir path: d / b32[0..2] / b32[2..32]
    let mut siv_key = [0u8; 64];
    siv_key[0..32].copy_from_slice(&mac_key);
    siv_key[32..64].copy_from_slice(&enc_key);

    let dir_path = |dir_id: &str| {
        let mut c = Aes256Siv::new_from_slice(&siv_key).expect("siv");
        let empty: [&[u8]; 0] = [];
        let ct = c.encrypt(empty, dir_id.as_bytes()).expect("enc dirid");
        let b32 = BASE32_NOPAD.encode(&Sha1::digest(&ct));
        cm_root.join("d").join(&b32[0..2]).join(&b32[2..32])
    };

    let root_dir = dir_path("");
    fs::create_dir_all(&root_dir).expect("mkdir root");

    // Write an encrypted file "hello.txt" (40 KiB, spans 2 chunks of 32 KiB)
    let mut siv = Aes256Siv::new_from_slice(&siv_key).expect("siv");
    let enc_fname = format!(
        "{}.c9r",
        URL_SAFE.encode(
            siv.encrypt([b"".as_slice()], b"hello.txt")
                .expect("enc name")
        )
    );
    let plaintext: Vec<u8> = (0..40_000usize).map(|i| (i % 251) as u8).collect();
    let header_nonce = [0x44u8; 12];
    let file_key = [0x55u8; 32];
    let mut hdr_pt = [0xFFu8; 40];
    hdr_pt[8..40].copy_from_slice(&file_key);
    let hdr_ct = Aes256Gcm::new((&enc_key).into())
        .encrypt(AesNonce::from_slice(&header_nonce), hdr_pt.as_slice())
        .expect("enc header");

    let mut file_bytes = Vec::new();
    file_bytes.extend_from_slice(&header_nonce);
    file_bytes.extend_from_slice(&hdr_ct);

    let chunk_cipher = Aes256Gcm::new((&file_key).into());
    for (idx, chunk) in plaintext.chunks(32_768).enumerate() {
        let mut cn = [0x66u8; 12];
        cn[0] = idx as u8;
        let mut aad = [0u8; 20];
        aad[0..8].copy_from_slice(&(idx as u64).to_be_bytes());
        aad[8..20].copy_from_slice(&header_nonce);
        let ct = chunk_cipher
            .encrypt(
                AesNonce::from_slice(&cn),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .expect("enc chunk");
        file_bytes.extend_from_slice(&cn);
        file_bytes.extend_from_slice(&ct);
    }
    fs::write(root_dir.join(&enc_fname), &file_bytes).expect("write cm file");

    // Wrong password rejected.
    assert!(matches!(
        CryptomatorVault::open(&cm_root, "wrong-password"),
        Err(VaultError::InvalidCredentials)
    ));

    // Open, list, and export!
    let cm = CryptomatorVault::open(&cm_root, password).expect("open cryptomator v8");
    let entries = cm.list_dir("/").expect("list root");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].kind, EntryKind::File);
    assert_eq!(entries[0].size, plaintext.len() as u64);

    let out = dir.path().join("exported_hello.txt");
    let written = cm.export_file("/hello.txt", &out).expect("export cm file");
    assert_eq!(written, plaintext.len() as u64);
    assert_eq!(fs::read(&out).expect("read exported"), plaintext);
}
