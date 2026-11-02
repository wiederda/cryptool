//! PQC-Modus außerhalb von OpenPGP: ML-KEM-768 + HKDF-SHA256 + XChaCha20-Poly1305.
//!
//! Das Format ist bewusst eigenständig und versioniert. Es kombiniert ausschließlich
//! standardisierte Bausteine:
//!
//! - **ML-KEM-768** (FIPS 203) zur Schlüsseleinigung (KEM),
//! - **HKDF-SHA256** (RFC 5869) zur Ableitung des symmetrischen Schlüssels,
//! - **XChaCha20-Poly1305** (RFC 8439 in der XChaCha-Variante) als AEAD/STREAM.
//!
//! Es handelt sich nicht um eine selbst entworfene Hybrid-Kombination: Es gibt genau
//! ein KEM und ein DEM. Die Authentizität öffentlicher Schlüssel muss außerhalb des
//! Formats sichergestellt werden (z. B. über einen vertrauenswürdigen Kanal); anders
//! als bei OpenPGP gibt es hier keine Selbstsignatur des Schlüssels.
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
//! können aber auch binär gelesen werden. Der geheime Schlüssel enthält nur den
//! 64-Byte-Seed von ML-KEM-768; dieser wird mit Argon2id und
//! XChaCha20-Poly1305 passphrasegeschützt.

use std::cell::Cell;
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
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::engine::{
    extract_archive, remap_error, scan_dir, with_part_dir, with_part_file, write_dir_stream,
    write_file_stream, Dec, DecryptReader, Enc, EncryptWriter, Error, Fail, Progress, Report,
    Result, Tracker, TAG_LEN,
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
const KEY_VERSION: u8 = 1;
const KEY_ALG_MLKEM768: u8 = 1;

const PUBLIC_KEY_LABEL: &str = "CRYPTOOL PQC PUBLIC KEY";
const SECRET_KEY_LABEL: &str = "CRYPTOOL PQC SECRET KEY";
const MESSAGE_LABEL: &str = "CRYPTOOL PQC MESSAGE";

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

// --------------------------------------------------------------- Schlüsseldateien

pub struct PublicKey {
    pub user_id: String,
    key: EncapsulationKey<MlKem768>,
}

struct SecretKeyFile {
    user_id: String,
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

fn parse_public_key(blob: &[u8]) -> Result<PublicKey> {
    let mut pos = 0usize;
    if take(blob, &mut pos, 4)? != PUBLIC_MAGIC {
        return Err(invalid("Keine cryptool-PQC-Schlüsseldatei"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_VERSION {
        return Err(invalid("Nicht unterstützte PQC-Schlüsselversion"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLKEM768 {
        return Err(invalid("Nicht unterstützter PQC-Schlüsselalgorithmus"));
    }
    let id_len = read_u16(blob, &mut pos)? as usize;
    let user_id = std::str::from_utf8(take(blob, &mut pos, id_len)?)
        .map_err(|_| invalid("Nutzerkennung im Schlüssel ist kein UTF-8"))?
        .to_owned();
    let ek_bytes = take(blob, &mut pos, KEM_EK_LEN)?;
    if pos != blob.len() {
        return Err(invalid("PQC-Schlüsseldatei enthält unerwartete Daten"));
    }
    let raw: ml_kem::Key<EncapsulationKey<MlKem768>> = ek_bytes
        .try_into()
        .map_err(|_| invalid("Öffentlicher ML-KEM-Schlüssel hat eine ungültige Länge"))?;
    let key = EncapsulationKey::<MlKem768>::new(&raw)
        .map_err(|_| invalid("Öffentlicher ML-KEM-Schlüssel ist ungültig"))?;
    Ok(PublicKey { user_id, key })
}

fn parse_secret_key(blob: &[u8]) -> Result<SecretKeyFile> {
    let mut pos = 0usize;
    if take(blob, &mut pos, 4)? != SECRET_MAGIC {
        return Err(invalid("Keine cryptool-PQC-Schlüsseldatei"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_VERSION {
        return Err(invalid("Nicht unterstützte PQC-Schlüsselversion"));
    }
    if take(blob, &mut pos, 1)?[0] != KEY_ALG_MLKEM768 {
        return Err(invalid("Nicht unterstützter PQC-Schlüsselalgorithmus"));
    }
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
    if ct_len != KEM_SEED_LEN + TAG_LEN {
        return Err(invalid("Ungültige Länge des geschützten PQC-Schlüssels"));
    }
    let seed_ct = take(blob, &mut pos, ct_len)?.to_vec();
    if pos != blob.len() {
        return Err(invalid("PQC-Schlüsseldatei enthält unerwartete Daten"));
    }
    Ok(SecretKeyFile {
        user_id,
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
) -> Result<Zeroizing<Vec<u8>>> {
    let key = cryptool_core::derive_key(passphrase.expose_secret(), salt, m_kib, t, p)
        .map_err(Error::Kdf)?;
    let cipher = cryptool_core::xchacha20poly1305(&key);
    let seed = cipher
        .decrypt(GenericArray::from_slice(nonce), seed_ct)
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    if seed.len() != KEM_SEED_LEN {
        return Err(Error::Corrupt);
    }
    Ok(Zeroizing::new(seed))
}

/// Lädt einen öffentlichen PQC-Schlüssel (ASCII-Armor oder binär).
pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    parse_public_key(&read_key_file(path, PUBLIC_KEY_LABEL)?)
}

fn load_secret_seed(path: &Path, passphrase: SecretString) -> Result<(String, Zeroizing<Vec<u8>>)> {
    let blob = read_key_file(path, SECRET_KEY_LABEL)?;
    let parsed = parse_secret_key(&blob)?;
    let seed = decrypt_seed(
        passphrase,
        &parsed.salt,
        &parsed.nonce,
        &parsed.seed_ct,
        parsed.m_kib,
        parsed.t,
        parsed.p,
    )?;
    Ok((parsed.user_id, seed))
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
    let seed = dk
        .to_seed()
        .ok_or_else(|| invalid("ML-KEM-Schlüssel konnte nicht serialisiert werden"))?;

    // Öffentlicher Schlüssel: Nutzerkennung + roher Encapsulation-Key.
    let ek_bytes = ek.to_bytes();
    let mut public_blob = Vec::with_capacity(8 + user_id.len() + KEM_EK_LEN);
    public_blob.extend_from_slice(PUBLIC_MAGIC);
    public_blob.push(KEY_VERSION);
    public_blob.push(KEY_ALG_MLKEM768);
    public_blob.extend_from_slice(&(user_id.len() as u16).to_le_bytes());
    public_blob.extend_from_slice(user_id.as_bytes());
    public_blob.extend_from_slice(ek_bytes.as_slice());

    // Geheimer Schlüssel: Seed mit Argon2id + XChaCha20-Poly1305 geschützt.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; 24];
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = cryptool_core::derive_key(passphrase.expose_secret(), &salt, KDF_M_KIB, KDF_T, KDF_P)
        .map_err(Error::Kdf)?;
    let cipher = cryptool_core::xchacha20poly1305(&key);
    let seed_ct = cipher
        .encrypt(GenericArray::from_slice(&nonce), seed.as_slice())
        .map_err(|_| Error::Crypto)?;

    let mut secret_blob =
        Vec::with_capacity(8 + user_id.len() + 12 + SALT_LEN + 24 + 4 + KEM_SEED_LEN + TAG_LEN);
    secret_blob.extend_from_slice(SECRET_MAGIC);
    secret_blob.push(KEY_VERSION);
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
    let (_user_id, seed) = load_secret_seed(secret_key_file, passphrase)?;
    let seed: Seed = seed
        .as_slice()
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
}
