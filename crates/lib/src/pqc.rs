//! PQC-Modus außerhalb von OpenPGP: ML-KEM-768 + HKDF-SHA256 + XChaCha20-Poly1305
//! sowie ML-DSA-65 für abgetrennte Dateisignaturen.
//!
//! Das Format ist bewusst eigenständig und versioniert. Es kombiniert ausschließlich
//! standardisierte Bausteine:
//!
//! - **ML-KEM-768** (FIPS 203) zur Schlüsseleinigung (KEM),
//! - **HKDF-SHA256** (RFC 5869) zur Ableitung des symmetrischen Schlüssels,
//! - **XChaCha20-Poly1305** (RFC 8439 in der XChaCha-Variante) als AEAD/STREAM,
//! - **ML-DSA-65** (FIPS 204) zum Signieren und Prüfen von Dateien.
//!
//! Es handelt sich nicht um eine selbst entworfene Hybrid-Kombination: Es gibt genau
//! ein KEM, ein DEM und ein Signaturverfahren. Die Authentizität öffentlicher
//! Schlüssel muss außerhalb des Formats sichergestellt werden (z. B. über einen
//! vertrauenswürdigen Kanal); anders als bei OpenPGP gibt es hier keine
//! Selbstsignatur des Schlüssels.
//!
//! ## Nachrichtenformat (alle Zahlen little-endian)
//!
//! ```text
//!  0..4    Magic "CTPQ"
//!  4       Version (1)
//!  5       KEM-ID (1 = ML-KEM-768)
//!  6       KDF-ID (1 = HKDF-SHA256)
//!  7       Cipher-ID (1 = XChaCha20-Poly1305)
//!  8       Flags: 0 = einzelne Datei, 3 = Ordner (tar + zstd)
//!  9..13   Chunk-Größe (Klartext, Bytes)
//! 13..29   Salt für HKDF (16 Bytes)
//! 29..48   Nonce-Präfix für STREAM (19 Bytes)
//! 48..1136 ML-KEM-Ciphertext (1088 Bytes)
//! ```
//!
//! Danach folgen die Chunks (je Klartext-Chunk + 16 Byte Tag). Der Header ist als
//! AAD an jeden Chunk gebunden. Bei Ordnern ist der Klartext ein zstd-komprimiertes
//! tar-Archiv, wie beim CTX-Modus.
//!
//! ## Schlüsseldateien
//!
//! Öffentliche und geheime Schlüssel werden als ASCII-Armor (Base64) geschrieben,
//! können aber auch binär gelesen werden. Version 1 enthält nur den 64-Byte-Seed
//! von ML-KEM-768. Version 2 enthält zusätzlich einen ML-DSA-65-Schlüssel; der
//! geheime Schlüssel speichert beide Seeds (KEM + Signatur) mit Argon2id und
//! XChaCha20-Poly1305 passphrasegeschützt.
//!
//! ## Signaturdateien
//!
//! ```text
//!  0..4    Magic "CTSG"
//!  4       Version (1)
//!  5       Signatur-ID (1 = ML-DSA-65)
//!  6       Flags (0)
//!  7..9    Länge der Unterzeichnerkennung (u16)
//!  9..     Unterzeichnerkennung, Signaturlänge (u32), Signatur
//! ```

use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, OsRng};
use hkdf::Hkdf;
use ml_dsa::signature::{DigestSigner, DigestVerifier};
use ml_dsa::{
    KeyExport as DsaKeyExport, KeyInit as DsaKeyInit, Keypair as DsaKeypair, MlDsa65,
    Signature as MlDsaSignature, SignatureEncoding, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use sha2::{Digest, Sha256};
use shake::Update;
use zeroize::Zeroizing;

use crate::engine::{
    extract_archive, remap_error, scan_dir, with_part_dir, with_part_file, write_dir_stream,
    write_file_stream, Dec, DecryptReader, Enc, EncryptWriter, Error, Fail, Progress, Report,
    Result, Tracker, VerifyReport, TAG_LEN,
};
use crate::{ExposeSecret, SecretString};

/// Standard-Dateierweiterung für PQC-Nachrichten.
pub const EXTENSION: &str = "pqc";
/// Dateierweiterung für ASCII-Armor-Nachrichten (Textmodus).
pub const TEXT_EXTENSION: &str = "pqc.asc";
/// Endung für öffentliche Schlüsseldateien (z. B. `schluessel.pub.pqc`).
pub const PUBLIC_KEY_EXTENSION: &str = "pub.pqc";
/// Endung für geheime Schlüsseldateien (z. B. `schluessel.sec.pqc`).
pub const SECRET_KEY_EXTENSION: &str = "sec.pqc";
/// Endung für binäre abgetrennte Signaturen.
pub const SIGNATURE_EXTENSION: &str = "pqc.sig";
/// Endung für ASCII-Armor-Signaturen.
pub const SIGNATURE_ARMOR_EXTENSION: &str = "pqc.sig.asc";

const MAGIC: &[u8; 4] = b"CTPQ";
const VERSION: u8 = 1;
const KEM_MLKEM768: u8 = 1;
const KDF_HKDF_SHA256: u8 = 1;
const CIPHER_XCHACHA20POLY1305: u8 = 1;

const FLAG_TAR: u8 = 0b01;
const FLAG_ZSTD: u8 = 0b10;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 19; // 24 (XChaCha) - 5 (STREAM BE32)
const KEM_CT_LEN: usize = 1088; // ML-KEM-768
const HEADER_LEN: usize = 48 + KEM_CT_LEN;
const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
const KEM_EK_LEN: usize = 1184; // ML-KEM-768
const KEM_SEED_LEN: usize = 64;

const HKDF_INFO: &[u8] = b"cryptool-pqc-v1 ml-kem-768 xchacha20-poly1305";

const KDF_M_KIB: u32 = 64 * 1024;
const KDF_T: u32 = 3;
const KDF_P: u32 = 1;

const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_T: u32 = 10;
const MAX_P: u32 = 16;
const MIN_CHUNK: u32 = 1024;
const MAX_CHUNK: u32 = 64 * 1024 * 1024;

const PUBLIC_MAGIC: &[u8; 4] = b"CTPK";
const SECRET_MAGIC: &[u8; 4] = b"CTSK";
const KEY_VERSION_V1: u8 = 1;
const KEY_VERSION_V2: u8 = 2;
const KEY_ALG_MLKEM768: u8 = 1;
const KEY_ALG_MLDSA65: u8 = 1;

const DSA_VK_LEN: usize = 1952; // ML-DSA-65
const DSA_SEED_LEN: usize = 32;
const DSA_SIG_LEN: usize = 3309; // ML-DSA-65

const PUBLIC_KEY_LABEL: &str = "CRYPTOOL PQC PUBLIC KEY";
const SECRET_KEY_LABEL: &str = "CRYPTOOL PQC SECRET KEY";
const MESSAGE_LABEL: &str = "CRYPTOOL PQC MESSAGE";

const SIGNATURE_MAGIC: &[u8; 4] = b"CTSG";
const SIGNATURE_VERSION: u8 = 1;
const SIGNATURE_ALG_MLDSA65: u8 = 1;
const SIGNATURE_LABEL: &str = "CRYPTOOL PQC SIGNATURE";
const SIGNATURE_FLAGS: u8 = 0;

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

// --------------------------------------------------------------- Schlüsseldateien

pub struct PublicKey {
    pub user_id: String,
    key: EncapsulationKey<MlKem768>,
    signing_key: Option<MlDsaVerifyingKey<MlDsa65>>,
}

impl PublicKey {
    /// `true`, wenn der Schlüssel eine Signaturprüfung erlaubt (Format v2).
    pub fn can_verify(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Kurze, stabile Schlüsselkennung (erste 8 Byte des SHA-256-Fingerprints).
    pub fn key_id(&self) -> String {
        match &self.signing_key {
            Some(key) => dsa_key_id(key),
            None => kem_key_id(&self.key),
        }
    }
}

struct SecretKeyFile {
    user_id: String,
    has_signing_key: bool,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; 24],
    seed_ct: Vec<u8>,
}

fn armor(label: &str, data: &[u8]) -> String {
    let encoded = BASE64.encode(data);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // Base64 ist ASCII, daher ist from_utf8 hier immer erfolgreich.
        out.push_str(std::str::from_utf8(chunk).expect("base64 ist ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn unarmor(text: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut collecting = false;
    let mut payload = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line == begin {
            collecting = true;
        } else if line == end {
            break;
        } else if collecting {
            payload.push_str(line);
        }
    }
    if payload.is_empty() {
        return Err(invalid(format!(
            "Keine gültige {label}-Datei (ASCII-Armor nicht gefunden)"
        )));
    }
    BASE64
        .decode(payload)
        .map_err(|_| invalid(format!("{label}: Base64 ist ungültig")))
}

/// Liest eine Schlüsseldatei; ASCII-Armor und binäre Dateien werden akzeptiert.
fn read_key_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN ") {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| invalid(format!("{label}: Datei ist kein gültiges UTF-8")))?;
        unarmor(text, label)
    } else {
        Ok(bytes)
    }
}

fn write_key_file(path: &Path, label: &str, blob: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::OutputExists(path.to_path_buf()));
    }
    let armored = armor(label, blob);
    with_part_file(path, true, |w| {
        w.write_all(armored.as_bytes())?;
        Ok(())
    })
}

fn take<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| invalid("Schlüsseldatei ist abgeschnitten"))?;
    let slice = &data[*pos..end];
    *pos = end;
    Ok(slice)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        take(data, pos, 2)?.try_into().expect("zwei Bytes"),
    ))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        take(data, pos, 4)?.try_into().expect("vier Bytes"),
    ))
}

fn dsa_verifying_key(bytes: &[u8]) -> Result<MlDsaVerifyingKey<MlDsa65>> {
    let raw = bytes
        .try_into()
        .map_err(|_| invalid("Öffentlicher ML-DSA-Schlüssel hat eine ungültige Länge"))?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::new(&raw))
}

fn short_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn dsa_key_id(key: &MlDsaVerifyingKey<MlDsa65>) -> String {
    let bytes = DsaKeyExport::to_bytes(key);
    short_id(bytes.as_slice())
}

fn kem_key_id(key: &EncapsulationKey<MlKem768>) -> String {
    let bytes = key.to_bytes();
    short_id(bytes.as_slice())
}

fn parse_public_key(blob: &[u8]) -> Result<PublicKey> {
    let mut pos = 0usize;
    if take(blob, &mut pos, 4)? != PUBLIC_MAGIC {
        return Err(invalid("Keine cryptool-PQC-Schlüsseldatei"));
    }
    let version = take(blob, &mut pos, 1)?[0];
    if !matches!(version, KEY_VERSION_V1 | KEY_VERSION_V2) {
        return Err(invalid("Nicht unterstützte PQC-Schlüsselversion"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLKEM768 {
        return Err(invalid("Nicht unterstützter PQC-Schlüsselalgorithmus"));
    }
    let has_signing_key = if version == KEY_VERSION_V2 {
        if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLDSA65 {
            return Err(invalid("Nicht unterstützter PQC-Signaturalgorithmus"));
        }
        true
    } else {
        false
    };
    let id_len = read_u16(blob, &mut pos)? as usize;
    let user_id = std::str::from_utf8(take(blob, &mut pos, id_len)?)
        .map_err(|_| invalid("Nutzerkennung im Schlüssel ist kein UTF-8"))?
        .to_owned();
    let ek_bytes = take(blob, &mut pos, KEM_EK_LEN)?;
    let signing_key = if has_signing_key {
        Some(dsa_verifying_key(take(blob, &mut pos, DSA_VK_LEN)?)?)
    } else {
        None
    };
    if pos != blob.len() {
        return Err(invalid("PQC-Schlüsseldatei enthält unerwartete Daten"));
    }
    let raw: ml_kem::Key<EncapsulationKey<MlKem768>> = ek_bytes
        .try_into()
        .map_err(|_| invalid("Öffentlicher ML-KEM-Schlüssel hat eine ungültige Länge"))?;
    let key = EncapsulationKey::<MlKem768>::new(&raw)
        .map_err(|_| invalid("Öffentlicher ML-KEM-Schlüssel ist ungültig"))?;
    Ok(PublicKey {
        user_id,
        key,
        signing_key,
    })
}

fn parse_secret_key(blob: &[u8]) -> Result<SecretKeyFile> {
    let mut pos = 0usize;
    if take(blob, &mut pos, 4)? != SECRET_MAGIC {
        return Err(invalid("Keine cryptool-PQC-Schlüsseldatei"));
    }
    let version = take(blob, &mut pos, 1)?[0];
    if !matches!(version, KEY_VERSION_V1 | KEY_VERSION_V2) {
        return Err(invalid("Nicht unterstützte PQC-Schlüsselversion"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLKEM768 {
        return Err(invalid("Nicht unterstützter PQC-Schlüsselalgorithmus"));
    }
    let has_signing_key = if version == KEY_VERSION_V2 {
        if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLDSA65 {
            return Err(invalid("Nicht unterstützter PQC-Signaturalgorithmus"));
        }
        true
    } else {
        false
    };
    let id_len = read_u16(blob, &mut pos)? as usize;
    let user_id = std::str::from_utf8(take(blob, &mut pos, id_len)?)
        .map_err(|_| invalid("Nutzerkennung im Schlüssel ist kein UTF-8"))?
        .to_owned();
    let m_kib = read_u32(blob, &mut pos)?;
    let t = read_u32(blob, &mut pos)?;
    let p = read_u32(blob, &mut pos)?;
    if !(1..=MAX_M_KIB).contains(&m_kib) || !(1..=MAX_T).contains(&t) || !(1..=MAX_P).contains(&p) {
        return Err(invalid("Ungültige KDF-Parameter im PQC-Schlüssel"));
    }
    let salt: [u8; SALT_LEN] = take(blob, &mut pos, SALT_LEN)?
        .try_into()
        .expect("Salt-Länge");
    let nonce: [u8; 24] = take(blob, &mut pos, 24)?.try_into().expect("Nonce-Länge");
    let ct_len = read_u32(blob, &mut pos)? as usize;
    let seed_len = if has_signing_key {
        KEM_SEED_LEN + DSA_SEED_LEN
    } else {
        KEM_SEED_LEN
    };
    if ct_len != seed_len + TAG_LEN {
        return Err(invalid("Ungültige Länge des geschützten PQC-Schlüssels"));
    }
    let seed_ct = take(blob, &mut pos, ct_len)?.to_vec();
    if pos != blob.len() {
        return Err(invalid("PQC-Schlüsseldatei enthält unerwartete Daten"));
    }
    Ok(SecretKeyFile {
        user_id,
        has_signing_key,
        m_kib,
        t,
        p,
        salt,
        nonce,
        seed_ct,
    })
}

fn decrypt_seed(
    passphrase: SecretString,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; 24],
    seed_ct: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    seed_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let key = cryptool_core::derive_key(passphrase.expose_secret(), salt, m_kib, t, p)
        .map_err(Error::Kdf)?;
    let cipher = cryptool_core::xchacha20poly1305(&key);
    let seed = cipher
        .decrypt(GenericArray::from_slice(nonce), seed_ct)
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    if seed.len() != seed_len {
        return Err(Error::Corrupt);
    }
    Ok(Zeroizing::new(seed))
}

/// Lädt einen öffentlichen PQC-Schlüssel (ASCII-Armor oder binär).
pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    parse_public_key(&read_key_file(path, PUBLIC_KEY_LABEL)?)
}

fn load_secret_seed(
    path: &Path,
    passphrase: SecretString,
) -> Result<(String, bool, Zeroizing<Vec<u8>>)> {
    let blob = read_key_file(path, SECRET_KEY_LABEL)?;
    let parsed = parse_secret_key(&blob)?;
    let seed_len = if parsed.has_signing_key {
        KEM_SEED_LEN + DSA_SEED_LEN
    } else {
        KEM_SEED_LEN
    };
    let seed = decrypt_seed(
        passphrase,
        &parsed.salt,
        &parsed.nonce,
        &parsed.seed_ct,
        parsed.m_kib,
        parsed.t,
        parsed.p,
        seed_len,
    )?;
    Ok((parsed.user_id, parsed.has_signing_key, seed))
}

/// Erzeugt ein ML-KEM-768-Schlüsselpaar. Beide Dateien werden als ASCII-Armor
/// geschrieben; der geheime Schlüssel ist mit der Passphrase geschützt.
pub fn generate_key(
    user_id: &str,
    passphrase: SecretString,
    secret_out: &Path,
    public_out: &Path,
    force: bool,
) -> Result<()> {
    if user_id.len() > u16::MAX as usize {
        return Err(invalid("Nutzerkennung ist zu lang"));
    }
    for out in [secret_out, public_out] {
        if out.exists() && !force {
            return Err(Error::OutputExists(out.to_path_buf()));
        }
    }
    if secret_out == public_out {
        return Err(invalid(
            "Geheimer und öffentlicher Schlüssel benötigen getrennte Dateien",
        ));
    }

    let (dk, ek) = MlKem768::generate_keypair();
    let kem_seed = dk
        .to_seed()
        .ok_or_else(|| invalid("ML-KEM-Schlüssel konnte nicht serialisiert werden"))?;

    // Signaturschlüssel: ML-DSA-65 aus einem zufälligen 32-Byte-Seed.
    let mut dsa_seed = [0u8; DSA_SEED_LEN];
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut dsa_seed);
    let dsa_seed_array: ml_dsa::Seed = (&dsa_seed[..])
        .try_into()
        .map_err(|_| invalid("ML-DSA-Seed hat eine ungültige Länge"))?;
    let signing_key = MlDsaSigningKey::<MlDsa65>::from_seed(&dsa_seed_array);
    let verifying_key = signing_key.verifying_key();
    let vk_bytes = DsaKeyExport::to_bytes(&verifying_key);

    // Öffentlicher Schlüssel (v2): Nutzerkennung + ML-KEM- + ML-DSA-Schlüssel.
    let ek_bytes = ek.to_bytes();
    let mut public_blob = Vec::with_capacity(9 + user_id.len() + KEM_EK_LEN + DSA_VK_LEN);
    public_blob.extend_from_slice(PUBLIC_MAGIC);
    public_blob.push(KEY_VERSION_V2);
    public_blob.push(KEY_ALG_MLKEM768);
    public_blob.push(KEY_ALG_MLDSA65);
    public_blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
    public_blob.extend_from_slice(user_id.as_bytes());
    public_blob.extend_from_slice(ek_bytes.as_slice());
    public_blob.extend_from_slice(vk_bytes.as_slice());

    // Geheimer Schlüssel (v2): beide Seeds mit Argon2id + XChaCha20-Poly1305
    // geschützt.
    let mut seed_blob = Zeroizing::new(Vec::with_capacity(KEM_SEED_LEN + DSA_SEED_LEN));
    seed_blob.extend_from_slice(kem_seed.as_slice());
    seed_blob.extend_from_slice(&dsa_seed);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = cryptool_core::derive_key(passphrase.expose_secret(), &salt, KDF_M_KIB, KDF_T, KDF_P)
        .map_err(Error::Kdf)?;
    let cipher = cryptool_core::xchacha20poly1305(&key);
    let seed_ct = cipher
        .encrypt(GenericArray::from_slice(&nonce), seed_blob.as_slice())
        .map_err(|_| Error::Crypto)?;

    let mut secret_blob =
        Vec::with_capacity(9 + user_id.len() + 12 + SALT_LEN + 24 + 4 + seed_ct.len());
    secret_blob.extend_from_slice(SECRET_MAGIC);
    secret_blob.push(KEY_VERSION_V2);
    secret_blob.push(KEY_ALG_MLKEM768);
    secret_blob.push(KEY_ALG_MLDSA65);
    secret_blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
    secret_blob.extend_from_slice(user_id.as_bytes());
    secret_blob.extend_from_slice(&KDF_M_KIB.to_le_bytes());
    secret_blob.extend_from_slice(&KDF_T.to_le_bytes());
    secret_blob.extend_from_slice(&KDF_P.to_le_bytes());
    secret_blob.extend_from_slice(&salt);
    secret_blob.extend_from_slice(&nonce);
    secret_blob.extend_from_slice(&(seed_ct.len() as u32).to_le_bytes());
    secret_blob.extend_from_slice(&seed_ct);

    write_key_file(secret_out, SECRET_KEY_LABEL, &secret_blob, force)?;
    write_key_file(public_out, PUBLIC_KEY_LABEL, &public_blob, force)?;
    Ok(())
}

// ------------------------------------------------------------------- Nachrichten

#[derive(Debug, Clone)]
struct Header {
    version: u8,
    kem: u8,
    kdf: u8,
    cipher: u8,
    flags: u8,
    chunk_size: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    kem_ct: [u8; KEM_CT_LEN],
}

impl Header {
    fn generate(public: &PublicKey, flags: u8) -> Result<(Self, Zeroizing<[u8; 32]>)> {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let (ct, shared) = public.key.encapsulate();
        let mut kem_ct = [0u8; KEM_CT_LEN];
        kem_ct.copy_from_slice(ct.as_slice());
        let key = derive_key(shared.as_slice(), &salt)?;
        Ok((
            Self {
                version: VERSION,
                kem: KEM_MLKEM768,
                kdf: KDF_HKDF_SHA256,
                cipher: CIPHER_XCHACHA20POLY1305,
                flags,
                chunk_size: DEFAULT_CHUNK_SIZE,
                salt,
                nonce,
                kem_ct,
            },
            key,
        ))
    }

    fn is_dir(&self) -> bool {
        self.flags & FLAG_TAR != 0
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(MAGIC);
        b[4] = self.version;
        b[5] = self.kem;
        b[6] = self.kdf;
        b[7] = self.cipher;
        b[8] = self.flags;
        b[9..13].copy_from_slice(&self.chunk_size.to_le_bytes());
        b[13..29].copy_from_slice(&self.salt);
        b[29..48].copy_from_slice(&self.nonce);
        b[48..].copy_from_slice(&self.kem_ct);
        b
    }

    fn from_bytes(b: &[u8; HEADER_LEN]) -> Result<Self> {
        if &b[0..4] != MAGIC {
            return Err(Error::NotCryptoolFile);
        }
        let version = b[4];
        let flags = b[8];
        if version != VERSION
            || b[5] != KEM_MLKEM768
            || b[6] != KDF_HKDF_SHA256
            || b[7] != CIPHER_XCHACHA20POLY1305
            || !(flags == 0 || flags == FLAG_TAR | FLAG_ZSTD)
        {
            return Err(Error::Unsupported(version));
        }
        let chunk_size = u32::from_le_bytes(b[9..13].try_into().expect("vier Bytes"));
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
            return Err(Error::BadHeader);
        }
        Ok(Self {
            version,
            kem: b[5],
            kdf: b[6],
            cipher: b[7],
            flags,
            chunk_size,
            salt: b[13..29].try_into().expect("Salt-Länge"),
            nonce: b[29..48].try_into().expect("Nonce-Länge"),
            kem_ct: b[48..].try_into().expect("KEM-Ciphertext-Länge"),
        })
    }
}

fn derive_key(shared: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, &mut key[..])
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

fn read_header_from(r: &mut impl Read) -> Result<(Header, [u8; HEADER_LEN])> {
    let mut hb = [0u8; HEADER_LEN];
    r.read_exact(&mut hb).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::NotCryptoolFile
        } else {
            Error::Io(e)
        }
    })?;
    Ok((Header::from_bytes(&hb)?, hb))
}

/// Entschlüsselt den ML-KEM-Ciphertext aus dem Header und leitet den
/// symmetrischen Schlüssel ab.
fn message_key(
    header: &Header,
    secret_key_file: &Path,
    passphrase: SecretString,
) -> Result<Zeroizing<[u8; 32]>> {
    let (_user_id, _has_signing_key, seed) = load_secret_seed(secret_key_file, passphrase)?;
    let kem_seed = seed
        .as_slice()
        .get(..KEM_SEED_LEN)
        .ok_or_else(|| invalid("PQC-Schlüssel hat eine ungültige Länge"))?;
    let seed: Seed = kem_seed
        .try_into()
        .map_err(|_| invalid("PQC-Schlüssel hat eine ungültige Länge"))?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let shared = dk
        .decapsulate_slice(&header.kem_ct)
        .map_err(|_| invalid("ML-KEM-Ciphertext hat eine ungültige Länge"))?;
    derive_key(shared.as_slice(), &header.salt)
}

/// Verschlüsselt eine Datei oder einen Ordner für den Besitzer des öffentlichen
/// Schlüssels `recipient_key_file`.
pub fn encrypt_path(
    input: &Path,
    output: &Path,
    recipient_key_file: &Path,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<Report> {
    let public = load_public_key(recipient_key_file)?;

    let meta = fs::metadata(input)?;
    let plan = if meta.is_dir() {
        Some(scan_dir(input, output)?)
    } else {
        None
    };
    let total = plan.as_ref().map_or(meta.len(), |p| p.total());
    let skipped = plan.as_ref().map_or(0, |p| p.skipped());
    let flags = if plan.is_some() {
        FLAG_TAR | FLAG_ZSTD
    } else {
        0
    };

    let (header, key) = Header::generate(&public, flags)?;
    let hb = header.to_bytes();
    let enc = Enc::from_aead(
        cryptool_core::xchacha20poly1305(&key),
        GenericArray::from_slice(&header.nonce),
    );
    drop(key);

    let mut tracker = Tracker::new(0, total, on_progress);
    let chunk = header.chunk_size as usize;
    let res = with_part_file(output, force, |w| {
        w.write_all(&hb)?;
        let sink = EncryptWriter::new(&mut *w, enc, hb.to_vec(), chunk, cancel);
        match &plan {
            None => write_file_stream(input, sink, &mut tracker, cancel),
            Some(plan) => write_dir_stream(plan, sink, &mut tracker, cancel),
        }
    });
    match res {
        Ok(()) => Ok(Report { skipped }),
        Err(_) if cancel.load(Ordering::Relaxed) => Err(Error::Canceled),
        Err(e) => Err(e),
    }
}

/// Entschlüsselt eine PQC-Nachricht. Bei Ordnern ist `output` der neue Ordner.
pub fn decrypt_path(
    input: &Path,
    output: &Path,
    secret_key_file: &Path,
    passphrase: SecretString,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<()> {
    let mut file = File::open(input)?;
    let file_len = file.metadata()?.len();
    let (header, hb) = read_header_from(&mut file)?;
    let total = file_len.saturating_sub(HEADER_LEN as u64);

    let key = message_key(&header, secret_key_file, passphrase)?;
    let dec = Dec::from_aead(
        cryptool_core::xchacha20poly1305(&key),
        GenericArray::from_slice(&header.nonce),
    );
    drop(key);

    let fail: Rc<Cell<Option<Fail>>> = Rc::new(Cell::new(None));
    let reader = DecryptReader::new(
        file,
        dec,
        hb.to_vec(),
        header.chunk_size as usize,
        cancel,
        Tracker::new(0, total, on_progress),
        Rc::clone(&fail),
    );
    let res = if header.is_dir() {
        with_part_dir(output, |part| extract_archive(reader, part))
    } else {
        with_part_file(output, force, |w| {
            let mut r = reader;
            io::copy(&mut r, w)?;
            Ok(())
        })
    };
    res.map_err(|e| remap_error(e, &fail))
}

/// Verschlüsselt UTF-8-Text und liefert eine ASCII-Armor-Nachricht.
pub fn encrypt_text(text: &str, recipient_key_file: &Path) -> Result<String> {
    let public = load_public_key(recipient_key_file)?;
    let (header, key) = Header::generate(&public, 0)?;
    let hb = header.to_bytes();
    let enc = Enc::from_aead(
        cryptool_core::xchacha20poly1305(&key),
        GenericArray::from_slice(&header.nonce),
    );
    drop(key);

    // Derselbe Chunked-STREAM-Aufbau wie bei Dateien, damit auch große Texte
    // und die Erkennung abgeschnittener Nachrichten identisch funktionieren.
    let cancel = AtomicBool::new(false);
    let mut blob = hb.to_vec();
    let mut sink = EncryptWriter::new(
        &mut blob,
        enc,
        hb.to_vec(),
        header.chunk_size as usize,
        &cancel,
    );
    sink.write_all(text.as_bytes())?;
    sink.finish()?;
    Ok(armor(MESSAGE_LABEL, &blob))
}

/// Entschlüsselt eine ASCII-Armor-PQC-Nachricht zu UTF-8-Text.
pub fn decrypt_text(
    armored: &str,
    secret_key_file: &Path,
    passphrase: SecretString,
) -> Result<String> {
    let blob = unarmor(armored, MESSAGE_LABEL)?;
    let mut cursor = Cursor::new(blob);
    let (header, hb) = read_header_from(&mut cursor)?;
    if header.is_dir() {
        return Err(invalid("Die Nachricht enthält ein Ordnerarchiv statt Text"));
    }
    let key = message_key(&header, secret_key_file, passphrase)?;
    let dec = Dec::from_aead(
        cryptool_core::xchacha20poly1305(&key),
        GenericArray::from_slice(&header.nonce),
    );
    drop(key);

    let cancel = AtomicBool::new(false);
    let fail: Rc<Cell<Option<Fail>>> = Rc::new(Cell::new(None));
    let mut noop = |_p: Progress| {};
    let mut reader = DecryptReader::new(
        cursor,
        dec,
        hb.to_vec(),
        header.chunk_size as usize,
        &cancel,
        Tracker::new(0, 0, &mut noop),
        Rc::clone(&fail),
    );
    let mut plain = Vec::new();
    reader
        .read_to_end(&mut plain)
        .map_err(|e| remap_error(Error::Io(e), &fail))?;
    String::from_utf8(plain).map_err(|_| invalid("Der entschlüsselte Inhalt ist kein UTF-8-Text"))
}

// ---------------------------------------------------------------- Signaturen

/// Liest eine Signaturdatei (binär oder ASCII-Armor).
fn read_signature(path: &Path) -> Result<(String, Vec<u8>)> {
    let blob = read_key_file(path, SIGNATURE_LABEL)?;
    let mut pos = 0usize;
    if take(&blob, &mut pos, 4)? != SIGNATURE_MAGIC {
        return Err(invalid("Keine cryptool-PQC-Signaturdatei"));
    }
    if take(&blob, &mut pos, 1)?[0] != SIGNATURE_VERSION {
        return Err(invalid("Nicht unterstützte PQC-Signaturversion"));
    }
    if take(&blob, &mut pos, 1)?[0] != SIGNATURE_ALG_MLDSA65 {
        return Err(invalid("Nicht unterstützter PQC-Signaturalgorithmus"));
    }
    if take(&blob, &mut pos, 1)?[0] != SIGNATURE_FLAGS {
        return Err(invalid("Unbekannte Flags in der PQC-Signaturdatei"));
    }
    let id_len = read_u16(&blob, &mut pos)? as usize;
    let signer = std::str::from_utf8(take(&blob, &mut pos, id_len)?)
        .map_err(|_| invalid("Unterzeichnerkennung ist kein UTF-8"))?
        .to_owned();
    let sig_len = read_u32(&blob, &mut pos)? as usize;
    if sig_len != DSA_SIG_LEN {
        return Err(invalid("Ungültige Länge der PQC-Signatur"));
    }
    let signature = take(&blob, &mut pos, sig_len)?.to_vec();
    if pos != blob.len() {
        return Err(invalid("PQC-Signaturdatei enthält unerwartete Daten"));
    }
    Ok((signer, signature))
}

/// Liest eine Datei blockweise, meldet Fortschritt und erlaubt Abbruch.
struct DigestReader<'a> {
    inner: File,
    tracker: Tracker<'a>,
    cancel: &'a AtomicBool,
}

impl Read for DigestReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other("abgebrochen"));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tracker.add(n as u64);
        }
        Ok(n)
    }
}

/// Signiert eine Datei mit dem geheimen ML-DSA-Schlüssel und schreibt eine
/// abgetrennte Signaturdatei (binär oder ASCII-Armor).
pub fn sign_path(
    input: &Path,
    output: &Path,
    secret_key_file: &Path,
    passphrase: SecretString,
    armored: bool,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<()> {
    if input.is_dir() {
        return Err(invalid("Signieren wird nur für einzelne Dateien unterstützt"));
    }
    let (user_id, has_signing_key, seed) = load_secret_seed(secret_key_file, passphrase)?;
    if !has_signing_key {
        return Err(invalid(
            "Der PQC-Schlüssel (Format v1) enthält keinen Signaturschlüssel; bitte ein neues Schlüsselpaar erzeugen",
        ));
    }
    let dsa_seed: ml_dsa::Seed = seed
        .as_slice()
        .get(KEM_SEED_LEN..)
        .ok_or_else(|| invalid("PQC-Schlüssel hat eine ungültige Länge"))?
        .try_into()
        .map_err(|_| invalid("ML-DSA-Seed hat eine ungültige Länge"))?;
    let signing_key = MlDsaSigningKey::<MlDsa65>::from_seed(&dsa_seed);

    let total = fs::metadata(input)?.len();
    let reader = RefCell::new(DigestReader {
        inner: File::open(input)?,
        tracker: Tracker::new(0, total, on_progress),
        cancel,
    });
    let io_err: RefCell<Option<Error>> = RefCell::new(None);
    let signature = signing_key.try_sign_digest(|hasher| {
        let mut r = reader.borrow_mut();
        let mut buf = [0u8; 64 * 1024];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) => {
                    *io_err.borrow_mut() = Some(Error::Io(e));
                    return Err(ml_dsa::signature::Error::new());
                }
            }
        }
        Ok(())
    });
    let signature = match signature {
        Ok(sig) => {
            if let Some(e) = io_err.into_inner() {
                return Err(e);
            }
            sig
        }
        Err(_) => {
            if let Some(e) = io_err.into_inner() {
                return Err(e);
            }
            return Err(if cancel.load(Ordering::Relaxed) {
                Error::Canceled
            } else {
                Error::Crypto
            });
        }
    };
    let encoded = signature.to_bytes();

    let mut blob = Vec::with_capacity(9 + user_id.len() + 4 + DSA_SIG_LEN);
    blob.extend_from_slice(SIGNATURE_MAGIC);
    blob.push(SIGNATURE_VERSION);
    blob.push(SIGNATURE_ALG_MLDSA65);
    blob.push(SIGNATURE_FLAGS);
    blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
    blob.extend_from_slice(user_id.as_bytes());
    blob.extend_from_slice(&(DSA_SIG_LEN as u32).to_le_bytes());
    blob.extend_from_slice(encoded.as_slice());

    with_part_file(output, force, |w| {
        if armored {
            w.write_all(armor(SIGNATURE_LABEL, &blob).as_bytes())?;
        } else {
            w.write_all(&blob)?;
        }
        Ok(())
    })
}

/// Prüft eine abgetrennte PQC-Signatur gegen eine Datei.
pub fn verify_path(
    input: &Path,
    signature_file: &Path,
    public_key_file: &Path,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<VerifyReport> {
    if input.is_dir() {
        return Err(invalid("Signaturprüfung wird nur für einzelne Dateien unterstützt"));
    }
    let public = load_public_key(public_key_file)?;
    let verifying_key = public.signing_key.as_ref().ok_or_else(|| {
        invalid("Der PQC-Schlüssel (Format v1) enthält keinen Signaturschlüssel")
    })?;
    let (signer, sig_bytes) = read_signature(signature_file)?;
    let signature = MlDsaSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| invalid("PQC-Signatur ist ungültig kodiert"))?;

    let total = fs::metadata(input)?.len();
    let reader = RefCell::new(DigestReader {
        inner: File::open(input)?,
        tracker: Tracker::new(0, total, on_progress),
        cancel,
    });
    let io_err: RefCell<Option<Error>> = RefCell::new(None);
    let result = verifying_key.verify_digest(
        |hasher| {
            let mut r = reader.borrow_mut();
            let mut buf = [0u8; 64 * 1024];
            loop {
                match r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(e) => {
                        *io_err.borrow_mut() = Some(Error::Io(e));
                        return Err(ml_dsa::signature::Error::new());
                    }
                }
            }
            Ok(())
        },
        &signature,
    );
    match result {
        Ok(()) => Ok(VerifyReport {
            signer: if signer.is_empty() {
                public.user_id.clone()
            } else {
                signer
            },
            key_id: public.key_id(),
            created: None,
        }),
        Err(_) => {
            if let Some(e) = io_err.into_inner() {
                return Err(e);
            }
            if cancel.load(Ordering::Relaxed) {
                Err(Error::Canceled)
            } else {
                Err(Error::SignatureInvalid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_progress() -> impl FnMut(Progress) {
        |_p: Progress| {}
    }

    #[test]
    fn file_dir_and_text_roundtrip() {
        let root = std::env::temp_dir().join("cryptool-pqc-rtrip-test");
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"HALLO WELT").unwrap();
        fs::write(src.join("sub").join("b.txt"), b"UNTERORDNER").unwrap();

        let secret_out = root.join("s.sec.pqc");
        let public_out = root.join("p.pub.pqc");
        let pw = SecretString::new("testpw".to_owned());
        generate_key(
            "Test <t@example.de>",
            pw.clone(),
            &secret_out,
            &public_out,
            true,
        )
        .unwrap();

        let cancel = AtomicBool::new(false);

        let file_in = root.join("datei.bin");
        fs::write(&file_in, b"geheime datei").unwrap();
        let file_enc = root.join("datei.bin.pqc");
        encrypt_path(
            &file_in,
            &file_enc,
            &public_out,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let file_ret = root.join("datei.ret");
        decrypt_path(
            &file_enc,
            &file_ret,
            &secret_out,
            pw.clone(),
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert_eq!(fs::read(&file_ret).unwrap(), b"geheime datei");

        let dir_enc = root.join("src.pqc");
        encrypt_path(
            &src,
            &dir_enc,
            &public_out,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let dir_ret = root.join("aus");
        decrypt_path(
            &dir_enc,
            &dir_ret,
            &secret_out,
            pw.clone(),
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert_eq!(fs::read(dir_ret.join("a.txt")).unwrap(), b"HALLO WELT");
        assert_eq!(
            fs::read(dir_ret.join("sub").join("b.txt")).unwrap(),
            b"UNTERORDNER"
        );

        let text = "Hallo PQC";
        let armored = encrypt_text(text, &public_out).unwrap();
        assert!(armored.starts_with("-----BEGIN CRYPTOOL PQC MESSAGE-----"));
        let plain = decrypt_text(&armored, &secret_out, pw).unwrap();
        assert_eq!(plain, text);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn large_text_roundtrip() {
        let root = std::env::temp_dir().join("cryptool-pqc-large-text-test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let secret_out = root.join("s.sec.pqc");
        let public_out = root.join("p.pub.pqc");
        let pw = SecretString::new("testpw".to_owned());
        generate_key("Test", pw.clone(), &secret_out, &public_out, true).unwrap();

        // Mehr als eine Chunk-Größe, damit die STREAM-Chunkung geprüft wird.
        let text = "Ä".repeat(3 * 1024 * 1024);
        let armored = encrypt_text(&text, &public_out).unwrap();
        let plain = decrypt_text(&armored, &secret_out, pw).unwrap();
        assert_eq!(plain, text);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let root = std::env::temp_dir().join("cryptool-pqc-wrongpw-test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let secret_out = root.join("s.sec.pqc");
        let public_out = root.join("p.pub.pqc");
        generate_key(
            "Test",
            SecretString::new("richtig".to_owned()),
            &secret_out,
            &public_out,
            true,
        )
        .unwrap();
        let data = root.join("d.txt");
        fs::write(&data, b"x").unwrap();
        let enc = root.join("d.pqc");
        encrypt_path(
            &data,
            &enc,
            &public_out,
            true,
            &mut no_progress(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let err = decrypt_path(
            &enc,
            &root.join("out"),
            &secret_out,
            SecretString::new("falsch".to_owned()),
            true,
            &mut no_progress(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(matches!(err, Error::WrongPasswordOrCorrupt));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let root = std::env::temp_dir().join("cryptool-pqc-sign-test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let secret_out = root.join("s.sec.pqc");
        let public_out = root.join("p.pub.pqc");
        let pw = SecretString::new("testpw".to_owned());
        generate_key(
            "Signer <s@example.de>",
            pw.clone(),
            &secret_out,
            &public_out,
            true,
        )
        .unwrap();

        let data = root.join("d.txt");
        fs::write(&data, b"zu signierende datei").unwrap();
        let cancel = AtomicBool::new(false);

        // Binäre Signatur
        let sig = root.join("d.txt.pqc.sig");
        sign_path(
            &data,
            &sig,
            &secret_out,
            pw.clone(),
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let report = verify_path(&data, &sig, &public_out, &mut no_progress(), &cancel).unwrap();
        assert_eq!(report.signer, "Signer <s@example.de>");
        assert!(!report.key_id.is_empty());
        assert!(report.created.is_none());

        // ASCII-Armor-Signatur
        let armored = root.join("d.txt.pqc.sig.asc");
        sign_path(
            &data,
            &armored,
            &secret_out,
            pw.clone(),
            true,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert!(fs::read_to_string(&armored)
            .unwrap()
            .starts_with("-----BEGIN CRYPTOOL PQC SIGNATURE-----"));
        verify_path(
            &data,
            &armored,
            &public_out,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();

        // Manipulierte Datei wird abgelehnt.
        fs::write(&data, b"manipuliert").unwrap();
        let err = verify_path(&data, &sig, &public_out, &mut no_progress(), &cancel).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));

        // Falscher öffentlicher Schlüssel wird abgelehnt.
        fs::write(&data, b"zu signierende datei").unwrap();
        let other_secret = root.join("o.sec.pqc");
        let other_public = root.join("o.pub.pqc");
        generate_key(
            "Andere <a@example.de>",
            pw,
            &other_secret,
            &other_public,
            true,
        )
        .unwrap();
        let err = verify_path(&data, &sig, &other_public, &mut no_progress(), &cancel).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));

        // Ordner werden abgelehnt.
        let dir = root.join("verzeichnis");
        fs::create_dir_all(&dir).unwrap();
        let err = sign_path(
            &dir,
            &root.join("dir.pqc.sig"),
            &secret_out,
            SecretString::new("testpw".to_owned()),
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));

        let _ = fs::remove_dir_all(&root);
    }

    /// Schreibt ein Schlüsselpaar im alten v1-Format (nur ML-KEM).
    fn write_v1_keypair(
        root: &Path,
        user_id: &str,
        passphrase: &SecretString,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        use chacha20poly1305::aead::rand_core::RngCore;
        let (dk, ek) = MlKem768::generate_keypair();
        let seed = dk.to_seed().unwrap();
        let ek_bytes = ek.to_bytes();

        let mut public_blob = Vec::new();
        public_blob.extend_from_slice(PUBLIC_MAGIC);
        public_blob.push(KEY_VERSION_V1);
        public_blob.push(KEY_ALG_MLKEM768);
        public_blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
        public_blob.extend_from_slice(user_id.as_bytes());
        public_blob.extend_from_slice(ek_bytes.as_slice());

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = cryptool_core::derive_key(
            passphrase.expose_secret(),
            &salt,
            KDF_M_KIB,
            KDF_T,
            KDF_P,
        )
        .unwrap();
        let seed_ct = cryptool_core::xchacha20poly1305(&key)
            .encrypt(GenericArray::from_slice(&nonce), seed.as_slice())
            .unwrap();

        let mut secret_blob = Vec::new();
        secret_blob.extend_from_slice(SECRET_MAGIC);
        secret_blob.push(KEY_VERSION_V1);
        secret_blob.push(KEY_ALG_MLKEM768);
        secret_blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
        secret_blob.extend_from_slice(user_id.as_bytes());
        secret_blob.extend_from_slice(&KDF_M_KIB.to_le_bytes());
        secret_blob.extend_from_slice(&KDF_T.to_le_bytes());
        secret_blob.extend_from_slice(&KDF_P.to_le_bytes());
        secret_blob.extend_from_slice(&salt);
        secret_blob.extend_from_slice(&nonce);
        secret_blob.extend_from_slice(&(seed_ct.len() as u32).to_le_bytes());
        secret_blob.extend_from_slice(&seed_ct);

        let secret_out = root.join("v1.sec.pqc");
        let public_out = root.join("v1.pub.pqc");
        write_key_file(&secret_out, SECRET_KEY_LABEL, &secret_blob, true).unwrap();
        write_key_file(&public_out, PUBLIC_KEY_LABEL, &public_blob, true).unwrap();
        (secret_out, public_out)
    }

    #[test]
    fn v1_keys_still_encrypt_but_cannot_sign() {
        let root = std::env::temp_dir().join("cryptool-pqc-v1-test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let pw = SecretString::new("testpw".to_owned());
        let (secret_out, public_out) = write_v1_keypair(&root, "Alt <a@example.de>", &pw);

        let public = load_public_key(&public_out).unwrap();
        assert!(!public.can_verify());

        let cancel = AtomicBool::new(false);
        let data = root.join("d.txt");
        fs::write(&data, b"v1 kompatibel").unwrap();
        let enc = root.join("d.pqc");
        encrypt_path(
            &data,
            &enc,
            &public_out,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let out = root.join("d.out");
        decrypt_path(
            &enc,
            &out,
            &secret_out,
            pw.clone(),
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"v1 kompatibel");

        let err = sign_path(
            &data,
            &root.join("d.pqc.sig"),
            &secret_out,
            pw,
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));

        let _ = fs::remove_dir_all(&root);
    }
}
