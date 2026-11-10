//! Audited C library FFI bindings (OpenSSL 3 `libcrypto` + ICU `libicuuc`).
//!
//! All cryptographic operations and Unicode NFC normalization delegate directly to
//! the system's FIPS/Cure53-reviewed OpenSSL 3.0 (`libcrypto`) and ICU (`libicuuc`)
//! shared libraries. No custom cryptographic algorithms are implemented in Rust.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use std::ptr;

use crate::error::{Result, VaultError};

#[repr(C)]
struct EvpCipher(c_void);
#[repr(C)]
struct EvpCipherCtx(c_void);
#[repr(C)]
struct EvpMd(c_void);
#[repr(C)]
struct OsslLibCtx(c_void);
#[repr(C)]
struct UNormalizer2(c_void);

const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x09;
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x0001;

#[link(name = "crypto")]
extern "C" {
    fn RAND_bytes(buf: *mut c_uchar, num: c_int) -> c_int;
    fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);

    fn EVP_PBE_scrypt(
        pass: *const c_char,
        passlen: usize,
        salt: *const c_uchar,
        saltlen: usize,
        N: u64,
        r: u64,
        p: u64,
        maxmem: u64,
        key: *mut c_uchar,
        keylen: usize,
    ) -> c_int;

    fn EVP_CIPHER_CTX_new() -> *mut EvpCipherCtx;
    fn EVP_CIPHER_CTX_free(ctx: *mut EvpCipherCtx);
    fn EVP_CIPHER_CTX_set_flags(ctx: *mut EvpCipherCtx, flags: c_int);
    fn EVP_CIPHER_CTX_ctrl(ctx: *mut EvpCipherCtx, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int;

    fn EVP_aes_256_gcm() -> *const EvpCipher;
    fn EVP_aes_256_cbc() -> *const EvpCipher;
    fn EVP_aes_256_wrap() -> *const EvpCipher;
    fn EVP_CIPHER_fetch(ctx: *mut OsslLibCtx, algorithm: *const c_char, properties: *const c_char) -> *mut EvpCipher;
    fn EVP_CIPHER_free(cipher: *mut EvpCipher);

    fn CMAC_CTX_new() -> *mut c_void;
    fn CMAC_CTX_free(ctx: *mut c_void);
    fn CMAC_Init(
        ctx: *mut c_void,
        key: *const c_void,
        keylen: usize,
        cipher: *const EvpCipher,
        impl_: *mut c_void,
    ) -> c_int;
    fn CMAC_Update(ctx: *mut c_void, data: *const c_void, dlen: usize) -> c_int;
    fn CMAC_Final(ctx: *mut c_void, out: *mut c_uchar, poutlen: *mut usize) -> c_int;

    fn EVP_EncryptInit_ex(
        ctx: *mut EvpCipherCtx,
        cipher: *const EvpCipher,
        impl_: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    fn EVP_EncryptInit_ex2(
        ctx: *mut EvpCipherCtx,
        cipher: *const EvpCipher,
        key: *const c_uchar,
        iv: *const c_uchar,
        params: *const c_void,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut EvpCipherCtx,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const c_uchar,
        inl: c_int,
    ) -> c_int;
    fn EVP_EncryptFinal_ex(ctx: *mut EvpCipherCtx, out: *mut c_uchar, outl: *mut c_int) -> c_int;

    fn EVP_DecryptInit_ex(
        ctx: *mut EvpCipherCtx,
        cipher: *const EvpCipher,
        impl_: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    fn EVP_DecryptInit_ex2(
        ctx: *mut EvpCipherCtx,
        cipher: *const EvpCipher,
        key: *const c_uchar,
        iv: *const c_uchar,
        params: *const c_void,
    ) -> c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EvpCipherCtx,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const c_uchar,
        inl: c_int,
    ) -> c_int;
    fn EVP_DecryptFinal_ex(ctx: *mut EvpCipherCtx, outm: *mut c_uchar, outl: *mut c_int) -> c_int;

    fn EVP_sha1() -> *const EvpMd;
    fn EVP_sha256() -> *const EvpMd;
    fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut c_uchar,
        size: *mut c_uint,
        type_: *const EvpMd,
        impl_: *mut c_void,
    ) -> c_int;
    fn HMAC(
        evp_md: *const EvpMd,
        key: *const c_void,
        key_len: c_int,
        d: *const c_uchar,
        n: usize,
        md: *mut c_uchar,
        md_len: *mut c_uint,
    ) -> *mut c_uchar;
}

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

const RTLD_DEFAULT: *mut c_void = ptr::null_mut();

#[link(name = "icuuc")]
extern "C" {}

type Unorm2GetNfcInstanceFn = unsafe extern "C" fn(p_error_code: *mut i32) -> *const UNormalizer2;
type Unorm2NormalizeFn = unsafe extern "C" fn(
    norm2: *const UNormalizer2,
    src: *const u16,
    length: i32,
    dest: *mut u16,
    capacity: i32,
    p_error_code: *mut i32,
) -> i32;

fn resolve_icu_fns() -> Option<(Unorm2GetNfcInstanceFn, Unorm2NormalizeFn)> {
    const CANDIDATES: &[(&[u8], &[u8])] = &[
        (b"unorm2_getNFCInstance\0", b"unorm2_normalize\0"),
        (b"unorm2_getNFCInstance_76\0", b"unorm2_normalize_76\0"),
        (b"unorm2_getNFCInstance_75\0", b"unorm2_normalize_75\0"),
        (b"unorm2_getNFCInstance_74\0", b"unorm2_normalize_74\0"),
        (b"unorm2_getNFCInstance_73\0", b"unorm2_normalize_73\0"),
        (b"unorm2_getNFCInstance_72\0", b"unorm2_normalize_72\0"),
        (b"unorm2_getNFCInstance_71\0", b"unorm2_normalize_71\0"),
        (b"unorm2_getNFCInstance_70\0", b"unorm2_normalize_70\0"),
        (b"unorm2_getNFCInstance_67\0", b"unorm2_normalize_67\0"),
        (b"unorm2_getNFCInstance_66\0", b"unorm2_normalize_66\0"),
    ];
    for (get_sym, norm_sym) in CANDIDATES {
        unsafe {
            let p_get = dlsym(RTLD_DEFAULT, get_sym.as_ptr() as *const c_char);
            let p_norm = dlsym(RTLD_DEFAULT, norm_sym.as_ptr() as *const c_char);
            if !p_get.is_null() && !p_norm.is_null() {
                let f_get: Unorm2GetNfcInstanceFn = std::mem::transmute(p_get);
                let f_norm: Unorm2NormalizeFn = std::mem::transmute(p_norm);
                return Some((f_get, f_norm));
            }
        }
    }
    None
}

struct CipherCtx(*mut EvpCipherCtx);

impl CipherCtx {
    fn new() -> Result<Self> {
        let p = unsafe { EVP_CIPHER_CTX_new() };
        if p.is_null() {
            return Err(VaultError::Malformed("EVP_CIPHER_CTX_new failed".into()));
        }
        Ok(CipherCtx(p))
    }
}

impl Drop for CipherCtx {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.0) }
    }
}

struct FetchedCipher(*mut EvpCipher);

impl FetchedCipher {
    fn aes_256_siv() -> Result<Self> {
        let name = b"AES-256-SIV\0";
        let p = unsafe { EVP_CIPHER_fetch(ptr::null_mut(), name.as_ptr() as *const c_char, ptr::null()) };
        if p.is_null() {
            return Err(VaultError::Unsupported("OpenSSL AES-256-SIV unavailable".into()));
        }
        Ok(FetchedCipher(p))
    }
}

impl Drop for FetchedCipher {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_free(self.0) }
    }
}

/// Securely zeroize memory using `OPENSSL_cleanse` (cannot be optimized out by compiler).
pub fn cleanse(buf: &mut [u8]) {
    if !buf.is_empty() {
        unsafe { OPENSSL_cleanse(buf.as_mut_ptr() as *mut c_void, buf.len()) }
    }
}

/// Constant-time slice comparison via `CRYPTO_memcmp`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    unsafe { CRYPTO_memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, a.len()) == 0 }
}

/// Fill `buf` from the OS-backed OpenSSL CSPRNG (`RAND_bytes`).
pub fn random_fill(buf: &mut [u8]) {
    let rc = unsafe { RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int) };
    assert_eq!(rc, 1, "RAND_bytes failed");
}

/// Derive a key with `EVP_PBE_scrypt`.
pub fn scrypt_derive(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32, out: &mut [u8]) -> Result<()> {
    let n = 1u64.checked_shl(log_n as u32).ok_or_else(|| VaultError::Unsupported("scrypt N overflow".into()))?;
    // Allow up to 512 MiB for scrypt memory.
    let maxmem: u64 = 512 * 1024 * 1024;
    let rc = unsafe {
        EVP_PBE_scrypt(
            password.as_ptr() as *const c_char,
            password.len(),
            salt.as_ptr(),
            salt.len(),
            n,
            r as u64,
            p as u64,
            maxmem,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if rc != 1 {
        return Err(VaultError::Unsupported("EVP_PBE_scrypt failed".into()));
    }
    Ok(())
}

/// RFC 3394 AES-256 Key Wrap (32-byte key -> 40-byte wrapped key).
pub fn aes256_wrap(kek: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 40]> {
    let ctx = CipherCtx::new()?;
    let mut out = [0u8; 40];
    let mut outlen: c_int = 0;
    let mut tmplen: c_int = 0;
    unsafe {
        EVP_CIPHER_CTX_set_flags(ctx.0, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if EVP_EncryptInit_ex(ctx.0, EVP_aes_256_wrap(), ptr::null_mut(), kek.as_ptr(), ptr::null()) != 1 {
            return Err(VaultError::Malformed("key wrap init".into()));
        }
        if EVP_EncryptUpdate(ctx.0, out.as_mut_ptr(), &mut outlen, key.as_ptr(), 32) != 1 {
            return Err(VaultError::Malformed("key wrap update".into()));
        }
        if EVP_EncryptFinal_ex(ctx.0, out.as_mut_ptr().add(outlen as usize), &mut tmplen) != 1 {
            return Err(VaultError::Malformed("key wrap final".into()));
        }
    }
    if (outlen + tmplen) != 40 {
        return Err(VaultError::Malformed("unexpected wrapped key size".into()));
    }
    Ok(out)
}

/// RFC 3394 AES-256 Key Unwrap (40-byte wrapped -> 32-byte key).
pub fn aes256_unwrap(kek: &[u8; 32], wrapped: &[u8], out: &mut [u8; 32]) -> Result<()> {
    if wrapped.len() != 40 {
        return Err(VaultError::Malformed("wrapped key length".into()));
    }
    let ctx = CipherCtx::new()?;
    let mut tmp = [0u8; 40];
    let mut outlen: c_int = 0;
    let mut tmplen: c_int = 0;
    let ok = unsafe {
        EVP_CIPHER_CTX_set_flags(ctx.0, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_DecryptInit_ex(ctx.0, EVP_aes_256_wrap(), ptr::null_mut(), kek.as_ptr(), ptr::null()) == 1
            && EVP_DecryptUpdate(ctx.0, tmp.as_mut_ptr(), &mut outlen, wrapped.as_ptr(), 40) == 1
            && EVP_DecryptFinal_ex(ctx.0, tmp.as_mut_ptr().add(outlen as usize), &mut tmplen) == 1
            && (outlen + tmplen) == 32
    };
    if !ok {
        cleanse(&mut tmp);
        return Err(VaultError::InvalidPassword);
    }
    out.copy_from_slice(&tmp[..32]);
    cleanse(&mut tmp);
    Ok(())
}

/// AES-256-GCM in-place encryption with 12-byte nonce and detached 16-byte tag.
pub fn aes256_gcm_encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16]> {
    let ctx = CipherCtx::new()?;
    let mut outlen: c_int = 0;
    let mut tag = [0u8; 16];
    let ok = unsafe {
        EVP_EncryptInit_ex(ctx.0, EVP_aes_256_gcm(), ptr::null_mut(), ptr::null(), ptr::null()) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_IVLEN, 12, ptr::null_mut()) == 1
            && EVP_EncryptInit_ex(ctx.0, ptr::null(), ptr::null_mut(), key.as_ptr(), nonce.as_ptr()) == 1
            && (aad.is_empty()
                || EVP_EncryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, aad.as_ptr(), aad.len() as c_int) == 1)
            && EVP_EncryptUpdate(ctx.0, buf.as_mut_ptr(), &mut outlen, buf.as_ptr(), buf.len() as c_int) == 1
            && EVP_EncryptFinal_ex(ctx.0, buf.as_mut_ptr().add(outlen as usize), &mut outlen) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_GET_TAG, 16, tag.as_mut_ptr() as *mut c_void) == 1
    };
    if !ok {
        return Err(VaultError::Malformed("AES-256-GCM encrypt failed".into()));
    }
    Ok(tag)
}

/// AES-256-GCM in-place decryption with 12-byte nonce and detached 16-byte tag.
pub fn aes256_gcm_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
    err_ctx: &'static str,
) -> Result<()> {
    let ctx = CipherCtx::new()?;
    let mut outlen: c_int = 0;
    let mut tag_copy = *tag;
    let ok = unsafe {
        EVP_DecryptInit_ex(ctx.0, EVP_aes_256_gcm(), ptr::null_mut(), ptr::null(), ptr::null()) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_IVLEN, 12, ptr::null_mut()) == 1
            && EVP_DecryptInit_ex(ctx.0, ptr::null(), ptr::null_mut(), key.as_ptr(), nonce.as_ptr()) == 1
            && (aad.is_empty()
                || EVP_DecryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, aad.as_ptr(), aad.len() as c_int) == 1)
            && EVP_DecryptUpdate(ctx.0, buf.as_mut_ptr(), &mut outlen, buf.as_ptr(), buf.len() as c_int) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_TAG, 16, tag_copy.as_mut_ptr() as *mut c_void) == 1
            && EVP_DecryptFinal_ex(ctx.0, buf.as_mut_ptr().add(outlen as usize), &mut outlen) == 1
    };
    if !ok {
        cleanse(buf);
        return Err(VaultError::Authentication(err_ctx));
    }
    Ok(())
}

fn aes256_cmac(key: &[u8; 32], data: &[u8]) -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut outlen: usize = 0;
    unsafe {
        let ctx = CMAC_CTX_new();
        if ctx.is_null() {
            return Err(VaultError::Malformed("CMAC_CTX_new".into()));
        }
        let ok = CMAC_Init(ctx, key.as_ptr() as *const c_void, 32, EVP_aes_256_cbc(), ptr::null_mut()) == 1
            && CMAC_Update(ctx, data.as_ptr() as *const c_void, data.len()) == 1
            && CMAC_Final(ctx, out.as_mut_ptr(), &mut outlen) == 1
            && outlen == 16;
        CMAC_CTX_free(ctx);
        if !ok {
            return Err(VaultError::Malformed("AES-256-CMAC failed".into()));
        }
    }
    Ok(out)
}

fn gf128_dbl(b: &mut [u8; 16]) {
    let carry = (b[0] >> 7) & 1;
    for i in 0..15 {
        b[i] = (b[i] << 1) | ((b[i + 1] >> 7) & 1);
    }
    b[15] = (b[15] << 1) ^ if carry == 1 { 0x87 } else { 0x00 };
}

/// RFC 5297 S2V for empty plaintext (with optional single AAD header).
fn s2v_empty_plaintext(mac_key: &[u8; 32], aad: Option<&[u8]>) -> Result<[u8; 16]> {
    let mut d = aes256_cmac(mac_key, &[0u8; 16])?;
    if let Some(ad) = aad {
        gf128_dbl(&mut d);
        let cm = aes256_cmac(mac_key, ad)?;
        for i in 0..16 {
            d[i] ^= cm[i];
        }
    }
    // sn is empty (len < 16): T = dbl(D) xor pad("") where pad("") = 0x80 || 0^15
    gf128_dbl(&mut d);
    d[0] ^= 0x80;
    aes256_cmac(mac_key, &d)
}

/// RFC 5297 AES-256-SIV encryption. Returns `SIV_tag(16) || ciphertext` matching Cryptomator / RFC 5297.
pub fn aes256_siv_encrypt(key: &[u8; 64], aad: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&key[..32]);
        let tag = s2v_empty_plaintext(&mac_key, aad)?;
        cleanse(&mut mac_key);
        return Ok(tag.to_vec());
    }
    let cipher = FetchedCipher::aes_256_siv()?;
    let ctx = CipherCtx::new()?;
    let mut ct = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    let mut outlen: c_int = 0;
    let mut tmplen: c_int = 0;
    let ok = unsafe {
        EVP_EncryptInit_ex2(ctx.0, cipher.0, key.as_ptr(), ptr::null(), ptr::null()) == 1
            && match aad {
                Some(ad) => {
                    if ad.is_empty() {
                        let dummy = 0u8;
                        EVP_EncryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, &dummy, 0) == 1
                    } else {
                        EVP_EncryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, ad.as_ptr(), ad.len() as c_int) == 1
                    }
                }
                None => true,
            }
            && EVP_EncryptUpdate(ctx.0, ct.as_mut_ptr(), &mut outlen, plaintext.as_ptr(), plaintext.len() as c_int) == 1
            && EVP_EncryptFinal_ex(ctx.0, ct.as_mut_ptr().add(outlen as usize), &mut tmplen) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_GET_TAG, 16, tag.as_mut_ptr() as *mut c_void) == 1
    };
    if !ok {
        return Err(VaultError::Malformed("AES-256-SIV encrypt failed".into()));
    }
    let mut out = Vec::with_capacity(16 + plaintext.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// RFC 5297 AES-256-SIV decryption of `SIV_tag(16) || ciphertext`.
pub fn aes256_siv_decrypt(key: &[u8; 64], aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(VaultError::Authentication("file name"));
    }
    let (tag, ct) = data.split_at(16);
    if ct.is_empty() {
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&key[..32]);
        let expected = s2v_empty_plaintext(&mac_key, aad)?;
        cleanse(&mut mac_key);
        if !ct_eq(&expected, tag) {
            return Err(VaultError::Authentication("file name"));
        }
        return Ok(Vec::new());
    }
    let mut tag_buf = [0u8; 16];
    tag_buf.copy_from_slice(tag);

    let cipher = FetchedCipher::aes_256_siv()?;
    let ctx = CipherCtx::new()?;
    let mut pt = vec![0u8; ct.len()];
    let mut outlen: c_int = 0;
    let mut tmplen: c_int = 0;
    let ok = unsafe {
        EVP_DecryptInit_ex2(ctx.0, cipher.0, key.as_ptr(), ptr::null(), ptr::null()) == 1
            && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_TAG, 16, tag_buf.as_mut_ptr() as *mut c_void) == 1
            && match aad {
                Some(ad) => {
                    if ad.is_empty() {
                        let dummy = 0u8;
                        EVP_DecryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, &dummy, 0) == 1
                    } else {
                        EVP_DecryptUpdate(ctx.0, ptr::null_mut(), &mut outlen, ad.as_ptr(), ad.len() as c_int) == 1
                    }
                }
                None => true,
            }
            && EVP_DecryptUpdate(ctx.0, pt.as_mut_ptr(), &mut outlen, ct.as_ptr(), ct.len() as c_int) == 1
            && EVP_DecryptFinal_ex(ctx.0, pt.as_mut_ptr().add(outlen as usize), &mut tmplen) == 1
    };
    if !ok {
        cleanse(&mut pt);
        return Err(VaultError::Authentication("file name"));
    }
    Ok(pt)
}

/// HMAC-SHA256 via OpenSSL `HMAC()`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut len: c_uint = 0;
    let p = unsafe {
        HMAC(
            EVP_sha256(),
            key.as_ptr() as *const c_void,
            key.len() as c_int,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    assert!(!p.is_null() && len == 32, "HMAC-SHA256 failed");
    out
}

/// SHA-1 digest (20 bytes) via OpenSSL `EVP_Digest()`, used only for Cryptomator's dirId path hashing.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut len: c_uint = 0;
    let rc = unsafe {
        EVP_Digest(
            data.as_ptr() as *const c_void,
            data.len(),
            out.as_mut_ptr(),
            &mut len,
            EVP_sha1(),
            ptr::null_mut(),
        )
    };
    assert!(rc == 1 && len == 20, "SHA1 failed");
    out
}

/// Unicode NFC normalization via ICU `unorm2_getNFCInstance` (resolved dynamically across ICU versions)
/// with a pure-Rust canonical composition fallback for common combining marks.
pub fn nfc_normalize(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    if let Some((get_nfc, normalize)) = resolve_icu_fns() {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let mut err: i32 = 0;
        let norm = unsafe { get_nfc(&mut err) };
        if err <= 0 && !norm.is_null() {
            let mut cap = (utf16.len() as i32).saturating_add(16);
            let mut dst = vec![0u16; cap as usize];
            let len = unsafe {
                normalize(norm, utf16.as_ptr(), utf16.len() as i32, dst.as_mut_ptr(), cap, &mut err)
            };
            if err == 15 {
                err = 0;
                cap = len + 4;
                dst.resize(cap as usize, 0);
                let len2 = unsafe {
                    normalize(norm, utf16.as_ptr(), utf16.len() as i32, dst.as_mut_ptr(), cap, &mut err)
                };
                dst.truncate(len2.max(0) as usize);
                if let Ok(out) = String::from_utf16(&dst) {
                    return out;
                }
            } else if err <= 0 && len >= 0 {
                dst.truncate(len as usize);
                if let Ok(out) = String::from_utf16(&dst) {
                    return out;
                }
            }
        }
    }
    fallback_nfc_compose(s)
}

fn fallback_nfc_compose(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(&next) = chars.peek() {
            if let Some(composed) = compose_pair(c, next) {
                chars.next();
                out.push(composed);
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn compose_pair(base: char, mark: char) -> Option<char> {
    match (base, mark) {
        ('a', '\u{0300}') => Some('à'),
        ('a', '\u{0301}') => Some('á'),
        ('a', '\u{0302}') => Some('â'),
        ('a', '\u{0303}') => Some('ã'),
        ('a', '\u{0308}') => Some('ä'),
        ('a', '\u{030a}') => Some('å'),
        ('e', '\u{0300}') => Some('è'),
        ('e', '\u{0301}') => Some('é'),
        ('e', '\u{0302}') => Some('ê'),
        ('e', '\u{0308}') => Some('ë'),
        ('i', '\u{0300}') => Some('ì'),
        ('i', '\u{0301}') => Some('í'),
        ('i', '\u{0302}') => Some('î'),
        ('i', '\u{0308}') => Some('ï'),
        ('n', '\u{0303}') => Some('ñ'),
        ('o', '\u{0300}') => Some('ò'),
        ('o', '\u{0301}') => Some('ó'),
        ('o', '\u{0302}') => Some('ô'),
        ('o', '\u{0303}') => Some('õ'),
        ('o', '\u{0308}') => Some('ö'),
        ('u', '\u{0300}') => Some('ù'),
        ('u', '\u{0301}') => Some('ú'),
        ('u', '\u{0302}') => Some('û'),
        ('u', '\u{0308}') => Some('ü'),
        ('c', '\u{0327}') => Some('ç'),
        ('A', '\u{0300}') => Some('À'),
        ('A', '\u{0301}') => Some('Á'),
        ('A', '\u{0308}') => Some('Ä'),
        ('E', '\u{0301}') => Some('É'),
        ('N', '\u{0303}') => Some('Ñ'),
        ('O', '\u{0308}') => Some('Ö'),
        ('U', '\u{0308}') => Some('Ü'),
        _ => None,
    }
}

/// Wrapper that cleanses its contents via `OPENSSL_cleanse` on drop.
pub struct SecretBuf<T: AsMut<[u8]>>(pub T);

impl<T: AsMut<[u8]>> SecretBuf<T> {
    pub fn new(v: T) -> Self {
        SecretBuf(v)
    }
}

impl<T: AsMut<[u8]>> std::ops::Deref for SecretBuf<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: AsMut<[u8]>> std::ops::DerefMut for SecretBuf<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsMut<[u8]>> Drop for SecretBuf<T> {
    fn drop(&mut self) {
        cleanse(self.0.as_mut());
    }
}

impl<T: AsMut<[u8]>> std::fmt::Debug for SecretBuf<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBuf(<redacted>)")
    }
}
