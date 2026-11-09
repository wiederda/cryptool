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
//! ML-KEM- und ML-DSA-Schlüssel werden getrennt gespeichert und verwenden
//! ausschließlich standardisierte Formate:
//!
//! - **Öffentliche Schlüssel:** SubjectPublicKeyInfo (SPKI) nach RFC 5280,
//!   wahlweise als PEM (`-----BEGIN PUBLIC KEY-----`) oder als DER.
//! - **Geheime Schlüssel:** passwortgeschütztes PKCS#8 nach RFC 5958
//!   (`-----BEGIN ENCRYPTED PRIVATE KEY-----`), ebenfalls als PEM oder DER.
//!
//! Es gibt demnach vier Schlüsseldateien: ML-KEM öffentlich/privat für die
//! Verschlüsselung und ML-DSA öffentlich/privat für Signaturen. Die
//! Schlüsseldateien enthalten keine cryptool-eigenen Metadaten mehr.
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
use chacha20poly1305::aead::OsRng;
use hkdf::Hkdf;
use ml_dsa::signature::{DigestSigner, DigestVerifier};
use ml_dsa::{
    Generate as DsaGenerate, Keypair as DsaKeypair, MlDsa65, Signature as MlDsaSignature,
    SignatureEncoding, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use pkcs8::{
    der::Decode as DerDecode, spki::AssociatedAlgorithmIdentifier, DecodePrivateKey,
    DecodePublicKey, Document, EncodePrivateKey, EncodePublicKey, EncryptedPrivateKeyInfoRef,
    LineEnding, PrivateKeyInfoRef, SecretDocument, SubjectPublicKeyInfoRef,
};
use sha2::{Digest, Sha256};
use shake::Update;
use zeroize::Zeroizing;

use crate::engine::{
    extract_archive, remap_error, scan_dir, with_part_dir, with_part_file,
    write_dir_stream, write_file_stream, Dec, DecryptReader, Enc, EncryptWriter, Error, Fail,
    Progress, Report, Result, Tracker, VerifyReport,
};
use crate::{ExposeSecret, SecretString};

/// Standard-Dateierweiterung für PQC-Nachrichten.
pub const EXTENSION: &str = "pqc";
/// Dateierweiterung für ASCII-Armor-Nachrichten (Textmodus).
pub const TEXT_EXTENSION: &str = "pqc.asc";
/// Endung für öffentliche ML-KEM-Schlüssel (SPKI, PEM).
pub const KEM_PUBLIC_KEY_EXTENSION: &str = "kem.pub.pem";
/// Endung für geheime ML-KEM-Schlüssel (verschlüsseltes PKCS#8, PEM).
pub const KEM_SECRET_KEY_EXTENSION: &str = "kem.sec.pem";
/// Endung für öffentliche ML-DSA-Schlüssel (SPKI, PEM).
pub const DSA_PUBLIC_KEY_EXTENSION: &str = "dsa.pub.pem";
/// Endung für geheime ML-DSA-Schlüssel (verschlüsseltes PKCS#8, PEM).
pub const DSA_SECRET_KEY_EXTENSION: &str = "dsa.sec.pem";
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

const HKDF_INFO: &[u8] = b"cryptool-pqc-v1 ml-kem-768 xchacha20-poly1305";

const MIN_CHUNK: u32 = 1024;
const MAX_CHUNK: u32 = 64 * 1024 * 1024;

const DSA_SIG_LEN: usize = 3309; // ML-DSA-65

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

/// Art einer PQC-Schlüsseldatei. Die Schlüssel für Verschlüsselung (ML-KEM)
/// und Signaturen (ML-DSA) werden getrennt gespeichert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    KemPublic,
    KemSecret,
    DsaPublic,
    DsaSecret,
}

impl KeyKind {
    pub fn is_public(self) -> bool {
        matches!(self, Self::KemPublic | Self::DsaPublic)
    }

    pub fn is_secret(self) -> bool {
        !self.is_public()
    }

    pub fn is_kem(self) -> bool {
        matches!(self, Self::KemPublic | Self::KemSecret)
    }

    pub fn is_dsa(self) -> bool {
        matches!(self, Self::DsaPublic | Self::DsaSecret)
    }
}

/// Ausgabeformat für Schlüsseldateien.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyFormat {
    /// Standard-PEM (`PUBLIC KEY` bzw. `ENCRYPTED PRIVATE KEY`).
    #[default]
    Pem,
    /// Binäres DER (SPKI bzw. verschlüsseltes PKCS#8).
    Der,
}

/// Geladener öffentlicher ML-KEM-Schlüssel.
pub struct PublicKey {
    key: EncapsulationKey<MlKem768>,
    id: String,
}

impl PublicKey {
    /// Kurze, stabile Schlüsselkennung (erste 8 Byte des SHA-256-Fingerprints
    /// über das SPKI-DER).
    pub fn key_id(&self) -> String {
        self.id.clone()
    }
}

/// Geladener öffentlicher ML-DSA-Schlüssel.
pub struct VerifyingKey {
    key: MlDsaVerifyingKey<MlDsa65>,
    id: String,
}

impl VerifyingKey {
    /// Kurze, stabile Schlüsselkennung (erste 8 Byte des SHA-256-Fingerprints
    /// über das SPKI-DER).
    pub fn key_id(&self) -> String {
        self.id.clone()
    }
}

fn short_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn strip_leading_space(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn kem_algorithm_oid() -> pkcs8::ObjectIdentifier {
    <MlKem768 as AssociatedAlgorithmIdentifier>::ALGORITHM_IDENTIFIER.oid
}

fn dsa_algorithm_oid() -> pkcs8::ObjectIdentifier {
    <MlDsa65 as AssociatedAlgorithmIdentifier>::ALGORITHM_IDENTIFIER.oid
}

/// Liest eine PEM- oder DER-kodierte SPKI-Datei und liefert das DER zurück.
fn public_key_der(bytes: &[u8]) -> Result<Vec<u8>> {
    let bytes = strip_leading_space(bytes);
    if bytes.starts_with(b"-----BEGIN ") {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| invalid("Öffentlicher Schlüssel: Datei ist kein gültiges UTF-8"))?;
        let (label, document) = Document::from_pem(text)
            .map_err(|_| invalid("Öffentlicher Schlüssel ist kein gültiges PEM/DER"))?;
        if label != "PUBLIC KEY" {
            return Err(invalid(format!(
                "Öffentlicher Schlüssel: unerwartete PEM-Kennung „{label}“"
            )));
        }
        Ok(document.as_bytes().to_vec())
    } else {
        Ok(bytes.to_vec())
    }
}

/// Erkennt, ob eine öffentliche Schlüsseldatei ein ML-KEM- oder ML-DSA-Schlüssel
/// ist. Das funktioniert ohne Passphrase, weil die Algorithmus-OID im SPKI steht.
pub fn detect_public_key_kind(bytes: &[u8]) -> Result<KeyKind> {
    let der = public_key_der(bytes)?;
    let spki = SubjectPublicKeyInfoRef::from_der(&der)
        .map_err(|_| invalid("Öffentlicher Schlüssel ist kein gültiges SPKI"))?;
    if spki.algorithm.oid == kem_algorithm_oid() {
        Ok(KeyKind::KemPublic)
    } else if spki.algorithm.oid == dsa_algorithm_oid() {
        Ok(KeyKind::DsaPublic)
    } else {
        Err(invalid("Unbekannter öffentlicher Schlüsselalgorithmus"))
    }
}

fn parse_public_key(path: &Path) -> Result<(KeyKind, Vec<u8>)> {
    let der = public_key_der(&fs::read(path)?)?;
    let spki = SubjectPublicKeyInfoRef::from_der(&der)
        .map_err(|_| invalid("Öffentlicher Schlüssel ist kein gültiges SPKI"))?;
    let kind = if spki.algorithm.oid == kem_algorithm_oid() {
        KeyKind::KemPublic
    } else if spki.algorithm.oid == dsa_algorithm_oid() {
        KeyKind::DsaPublic
    } else {
        return Err(invalid("Unbekannter öffentlicher Schlüsselalgorithmus"));
    };
    Ok((kind, der))
}

/// Entschlüsselt ein verschlüsseltes PKCS#8-Dokument. Ein falsches Passwort
/// wird als `WrongPasswordOrCorrupt` gemeldet.
fn decrypt_private_key(
    encrypted: &EncryptedPrivateKeyInfoRef<'_>,
    passphrase: &SecretString,
) -> Result<Vec<u8>> {
    let document = encrypted
        .decrypt(passphrase.expose_secret())
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    Ok(document.as_bytes().to_vec())
}

/// Liest eine geheime Schlüsseldatei (verschlüsseltes PKCS#8 als PEM oder DER).
/// Unverschlüsseltes PKCS#8 wird beim Import ebenfalls akzeptiert.
fn private_key_der(path: &Path, passphrase: &SecretString) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    let bytes = strip_leading_space(&bytes);
    if bytes.starts_with(b"-----BEGIN ") {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| invalid("Geheimer Schlüssel: Datei ist kein gültiges UTF-8"))?;
        let (label, document) = SecretDocument::from_pem(text)
            .map_err(|_| invalid("Geheimer Schlüssel ist kein gültiges PEM/DER"))?;
        match label {
            "ENCRYPTED PRIVATE KEY" => {
                let encrypted = EncryptedPrivateKeyInfoRef::try_from(document.as_bytes())
                    .map_err(|_| invalid("Verschlüsselter Schlüssel ist kein gültiges PKCS#8"))?;
                decrypt_private_key(&encrypted, passphrase)
            }
            "PRIVATE KEY" => Ok(document.as_bytes().to_vec()),
            other => Err(invalid(format!(
                "Geheimer Schlüssel: unerwartete PEM-Kennung „{other}“"
            ))),
        }
    } else if let Ok(encrypted) = EncryptedPrivateKeyInfoRef::try_from(bytes) {
        decrypt_private_key(&encrypted, passphrase)
    } else {
        PrivateKeyInfoRef::try_from(bytes)
            .map_err(|_| invalid("Geheimer Schlüssel ist kein gültiges PKCS#8"))?;
        Ok(bytes.to_vec())
    }
}

fn parse_private_key(path: &Path, passphrase: &SecretString) -> Result<(KeyKind, Vec<u8>)> {
    let der = private_key_der(path, passphrase)?;
    let info = PrivateKeyInfoRef::try_from(der.as_slice())
        .map_err(|_| invalid("Geheimer Schlüssel ist kein gültiges PKCS#8"))?;
    let kind = if info.algorithm.oid == kem_algorithm_oid() {
        KeyKind::KemSecret
    } else if info.algorithm.oid == dsa_algorithm_oid() {
        KeyKind::DsaSecret
    } else {
        return Err(invalid("Unbekannter geheimer Schlüsselalgorithmus"));
    };
    Ok((kind, der))
}

/// Lädt einen öffentlichen ML-KEM-Schlüssel (SPKI als PEM oder DER).
pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    let (kind, der) = parse_public_key(path)?;
    if kind != KeyKind::KemPublic {
        return Err(invalid(
            "Das ist ein ML-DSA-Schlüssel; zum Verschlüsseln wird ein ML-KEM-Schlüssel benötigt",
        ));
    }
    let key = EncapsulationKey::<MlKem768>::from_public_key_der(&der)
        .map_err(|_| invalid("Öffentlicher ML-KEM-Schlüssel ist ungültig"))?;
    Ok(PublicKey {
        key,
        id: short_id(&der),
    })
}

/// Lädt einen öffentlichen ML-DSA-Schlüssel (SPKI als PEM oder DER).
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let (kind, der) = parse_public_key(path)?;
    if kind != KeyKind::DsaPublic {
        return Err(invalid(
            "Das ist ein ML-KEM-Schlüssel; zum Prüfen wird ein ML-DSA-Schlüssel benötigt",
        ));
    }
    let key = MlDsaVerifyingKey::<MlDsa65>::from_public_key_der(&der)
        .map_err(|_| invalid("Öffentlicher ML-DSA-Schlüssel ist ungültig"))?;
    Ok(VerifyingKey {
        key,
        id: short_id(&der),
    })
}

fn load_kem_secret(path: &Path, passphrase: &SecretString) -> Result<DecapsulationKey<MlKem768>> {
    let (kind, der) = parse_private_key(path, passphrase)?;
    if kind != KeyKind::KemSecret {
        return Err(invalid(
            "Das ist ein ML-DSA-Schlüssel; zum Entschlüsseln wird ein ML-KEM-Schlüssel benötigt",
        ));
    }
    DecapsulationKey::<MlKem768>::from_pkcs8_der(&der)
        .map_err(|_| invalid("Geheimer ML-KEM-Schlüssel ist ungültig"))
}

fn load_dsa_secret(path: &Path, passphrase: &SecretString) -> Result<MlDsaSigningKey<MlDsa65>> {
    let (kind, der) = parse_private_key(path, passphrase)?;
    if kind != KeyKind::DsaSecret {
        return Err(invalid(
            "Das ist ein ML-KEM-Schlüssel; zum Signieren wird ein ML-DSA-Schlüssel benötigt",
        ));
    }
    MlDsaSigningKey::<MlDsa65>::from_pkcs8_der(&der)
        .map_err(|_| invalid("Geheimer ML-DSA-Schlüssel ist ungültig"))
}

fn write_key_bytes(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    with_part_file(path, force, |writer| {
        writer.write_all(bytes)?;
        Ok(())
    })
}

fn key_error(what: &str, error: impl std::fmt::Display) -> Error {
    invalid(format!("{what}: {error}"))
}

/// Erzeugt getrennte ML-KEM-768- und ML-DSA-65-Schlüsselpaare und schreibt vier
/// standardisierte Schlüsseldateien.
///
/// Öffentliche Schlüssel werden als SPKI (PEM oder DER) geschrieben, geheime
/// Schlüssel als passwortgeschütztes PKCS#8 (PEM oder DER).
#[allow(clippy::too_many_arguments)]
pub fn generate_key(
    passphrase: SecretString,
    kem_secret_out: &Path,
    kem_public_out: &Path,
    dsa_secret_out: &Path,
    dsa_public_out: &Path,
    format: KeyFormat,
    force: bool,
) -> Result<()> {
    if passphrase.expose_secret().is_empty() {
        return Err(invalid("Leere Passphrase ist nicht erlaubt"));
    }

    let outputs = [
        kem_secret_out,
        kem_public_out,
        dsa_secret_out,
        dsa_public_out,
    ];
    for (index, output) in outputs.iter().enumerate() {
        if outputs[index + 1..].contains(output) {
            return Err(invalid(
                "Die vier Schlüsseldateien benötigen getrennte Pfade",
            ));
        }
        if output.exists() && !force {
            return Err(Error::OutputExists(output.to_path_buf()));
        }
    }

    let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();
    let signing_key = MlDsaSigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();

    let (kem_public, kem_secret, dsa_public, dsa_secret) = match format {
        KeyFormat::Pem => {
            let kem_public = encapsulation_key
                .to_public_key_pem(LineEnding::LF)
                .map_err(|error| {
                    key_error("ML-KEM-Schlüssel konnte nicht kodiert werden", error)
                })?;
            let kem_secret = decapsulation_key
                .to_pkcs8_encrypted_pem(passphrase.expose_secret(), LineEnding::LF)
                .map_err(|error| {
                    key_error(
                        "Geheimer ML-KEM-Schlüssel konnte nicht kodiert werden",
                        error,
                    )
                })?;
            let dsa_public = verifying_key
                .to_public_key_pem(LineEnding::LF)
                .map_err(|error| {
                    key_error("ML-DSA-Schlüssel konnte nicht kodiert werden", error)
                })?;
            let dsa_secret = signing_key
                .to_pkcs8_encrypted_pem(passphrase.expose_secret(), LineEnding::LF)
                .map_err(|error| {
                    key_error(
                        "Geheimer ML-DSA-Schlüssel konnte nicht kodiert werden",
                        error,
                    )
                })?;
            (
                kem_public.into_bytes(),
                kem_secret.as_bytes().to_vec(),
                dsa_public.into_bytes(),
                dsa_secret.as_bytes().to_vec(),
            )
        }
        KeyFormat::Der => {
            let kem_public = encapsulation_key.to_public_key_der().map_err(|error| {
                key_error("ML-KEM-Schlüssel konnte nicht kodiert werden", error)
            })?;
            let kem_secret = decapsulation_key
                .to_pkcs8_encrypted_der(passphrase.expose_secret())
                .map_err(|error| {
                    key_error(
                        "Geheimer ML-KEM-Schlüssel konnte nicht kodiert werden",
                        error,
                    )
                })?;
            let dsa_public = verifying_key.to_public_key_der().map_err(|error| {
                key_error("ML-DSA-Schlüssel konnte nicht kodiert werden", error)
            })?;
            let dsa_secret = signing_key
                .to_pkcs8_encrypted_der(passphrase.expose_secret())
                .map_err(|error| {
                    key_error(
                        "Geheimer ML-DSA-Schlüssel konnte nicht kodiert werden",
                        error,
                    )
                })?;
            (
                kem_public.as_bytes().to_vec(),
                kem_secret.as_bytes().to_vec(),
                dsa_public.as_bytes().to_vec(),
                dsa_secret.as_bytes().to_vec(),
            )
        }
    };

    write_key_bytes(kem_secret_out, &kem_secret, force)?;
    write_key_bytes(kem_public_out, &kem_public, force)?;
    write_key_bytes(dsa_secret_out, &dsa_secret, force)?;
    write_key_bytes(dsa_public_out, &dsa_public, force)?;
    Ok(())
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

/// Liest eine Signaturdatei; ASCII-Armor und binäre Dateien werden akzeptiert.
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
    let decapsulation_key = load_kem_secret(secret_key_file, &passphrase)?;
    let shared = decapsulation_key
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
        return Err(invalid(
            "Signieren wird nur für einzelne Dateien unterstützt",
        ));
    }
    let signing_key = load_dsa_secret(secret_key_file, &passphrase)?;
    // Standardisierte PKCS#8-Schlüssel enthalten keine Nutzerkennung. Die
    // Signaturdatei bleibt trotzdem zum bisherigen Format kompatibel und
    // speichert hier eine leere Kennung.
    let user_id = String::new();

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
        return Err(invalid(
            "Signaturprüfung wird nur für einzelne Dateien unterstützt",
        ));
    }
    let verifying = load_verifying_key(public_key_file)?;
    let verifying_key = &verifying.key;
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
                verifying.key_id()
            } else {
                signer
            },
            key_id: verifying.key_id(),
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
    use std::path::PathBuf;

    fn no_progress() -> impl FnMut(Progress) {
        |_p: Progress| {}
    }

    struct KeyFiles {
        kem_secret: PathBuf,
        kem_public: PathBuf,
        dsa_secret: PathBuf,
        dsa_public: PathBuf,
    }

    fn generate(
        root: &Path,
        prefix: &str,
        passphrase: &SecretString,
        format: KeyFormat,
    ) -> KeyFiles {
        let ext = match format {
            KeyFormat::Pem => "pem",
            KeyFormat::Der => "der",
        };
        let keys = KeyFiles {
            kem_secret: root.join(format!("{prefix}-kem.sec.{ext}")),
            kem_public: root.join(format!("{prefix}-kem.pub.{ext}")),
            dsa_secret: root.join(format!("{prefix}-dsa.sec.{ext}")),
            dsa_public: root.join(format!("{prefix}-dsa.pub.{ext}")),
        };
        generate_key(
            passphrase.clone(),
            &keys.kem_secret,
            &keys.kem_public,
            &keys.dsa_secret,
            &keys.dsa_public,
            format,
            true,
        )
        .unwrap();
        keys
    }

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn encrypt_decrypt_file(root: &Path, keys: &KeyFiles, passphrase: &SecretString) {
        let cancel = AtomicBool::new(false);
        let input = root.join("datei.bin");
        fs::write(&input, b"geheime datei").unwrap();
        let encrypted = root.join("datei.bin.pqc");
        encrypt_path(
            &input,
            &encrypted,
            &keys.kem_public,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let output = root.join("datei.ret");
        decrypt_path(
            &encrypted,
            &output,
            &keys.kem_secret,
            passphrase.clone(),
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"geheime datei");
    }

    fn sign_verify_file(root: &Path, keys: &KeyFiles, passphrase: &SecretString) {
        let cancel = AtomicBool::new(false);
        let input = root.join("signatur.txt");
        fs::write(&input, b"zu signierende datei").unwrap();
        let signature = root.join("signatur.txt.pqc.sig");
        sign_path(
            &input,
            &signature,
            &keys.dsa_secret,
            passphrase.clone(),
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let report = verify_path(
            &input,
            &signature,
            &keys.dsa_public,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        assert_eq!(report.signer, report.key_id);
        assert!(!report.key_id.is_empty());
    }

    #[test]
    fn file_dir_and_text_roundtrip() {
        let root = temp_root("cryptool-pqc-rtrip-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "pem", &pw, KeyFormat::Pem);
        let cancel = AtomicBool::new(false);

        encrypt_decrypt_file(&root, &keys, &pw);

        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"HALLO WELT").unwrap();
        fs::write(src.join("sub").join("b.txt"), b"UNTERORDNER").unwrap();

        let dir_enc = root.join("src.pqc");
        encrypt_path(
            &src,
            &dir_enc,
            &keys.kem_public,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let dir_ret = root.join("aus");
        decrypt_path(
            &dir_enc,
            &dir_ret,
            &keys.kem_secret,
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
        let armored = encrypt_text(text, &keys.kem_public).unwrap();
        assert!(armored.starts_with("-----BEGIN CRYPTOOL PQC MESSAGE-----"));
        let plain = decrypt_text(&armored, &keys.kem_secret, pw).unwrap();
        assert_eq!(plain, text);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn large_text_roundtrip() {
        let root = temp_root("cryptool-pqc-large-text-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "pem", &pw, KeyFormat::Pem);

        // Mehr als eine Chunk-Größe, damit die STREAM-Chunkung geprüft wird.
        let text = "Ä".repeat(3 * 1024 * 1024);
        let armored = encrypt_text(&text, &keys.kem_public).unwrap();
        let plain = decrypt_text(&armored, &keys.kem_secret, pw).unwrap();
        assert_eq!(plain, text);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let root = temp_root("cryptool-pqc-wrongpw-test");
        let keys = generate(
            &root,
            "pem",
            &SecretString::new("richtig".to_owned()),
            KeyFormat::Pem,
        );
        let data = root.join("d.txt");
        fs::write(&data, b"x").unwrap();
        let enc = root.join("d.pqc");
        encrypt_path(
            &data,
            &enc,
            &keys.kem_public,
            true,
            &mut no_progress(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let err = decrypt_path(
            &enc,
            &root.join("out"),
            &keys.kem_secret,
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
        let root = temp_root("cryptool-pqc-sign-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "pem", &pw, KeyFormat::Pem);
        let cancel = AtomicBool::new(false);

        sign_verify_file(&root, &keys, &pw);

        let data = root.join("d.txt");
        fs::write(&data, b"zu signierende datei").unwrap();
        let sig = root.join("d.txt.pqc.sig");
        sign_path(
            &data,
            &sig,
            &keys.dsa_secret,
            pw.clone(),
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();

        // ASCII-Armor-Signatur
        let armored = root.join("d.txt.pqc.sig.asc");
        sign_path(
            &data,
            &armored,
            &keys.dsa_secret,
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
            &keys.dsa_public,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();

        // Manipulierte Datei wird abgelehnt.
        fs::write(&data, b"manipuliert").unwrap();
        let err =
            verify_path(&data, &sig, &keys.dsa_public, &mut no_progress(), &cancel).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));

        // Falscher öffentlicher Schlüssel wird abgelehnt.
        fs::write(&data, b"zu signierende datei").unwrap();
        let other = generate(&root, "other", &pw, KeyFormat::Pem);
        let err =
            verify_path(&data, &sig, &other.dsa_public, &mut no_progress(), &cancel).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));

        // Ordner werden abgelehnt.
        let dir = root.join("verzeichnis");
        fs::create_dir_all(&dir).unwrap();
        let err = sign_path(
            &dir,
            &root.join("dir.pqc.sig"),
            &keys.dsa_secret,
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

    #[test]
    fn pem_key_files_are_standardized() {
        let root = temp_root("cryptool-pqc-pem-format-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "pem", &pw, KeyFormat::Pem);

        for path in [&keys.kem_public, &keys.dsa_public] {
            let text = fs::read_to_string(path).unwrap();
            assert!(text.starts_with("-----BEGIN PUBLIC KEY-----"), "{text}");
            assert!(text.trim_end().ends_with("-----END PUBLIC KEY-----"));
        }
        for path in [&keys.kem_secret, &keys.dsa_secret] {
            let text = fs::read_to_string(path).unwrap();
            assert!(
                text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
                "{text}"
            );
            assert!(text
                .trim_end()
                .ends_with("-----END ENCRYPTED PRIVATE KEY-----"));
            assert!(!text.contains("CRYPTOOL"));
        }

        assert_eq!(
            detect_public_key_kind(&fs::read(&keys.kem_public).unwrap()).unwrap(),
            KeyKind::KemPublic
        );
        assert_eq!(
            detect_public_key_kind(&fs::read(&keys.dsa_public).unwrap()).unwrap(),
            KeyKind::DsaPublic
        );

        // Öffentliche und geheime Schlüssel lassen sich über die standardisierten
        // Formate erneut laden.
        load_public_key(&keys.kem_public).unwrap();
        load_verifying_key(&keys.dsa_public).unwrap();
        load_kem_secret(&keys.kem_secret, &pw).unwrap();
        load_dsa_secret(&keys.dsa_secret, &pw).unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn der_key_files_are_standardized_and_work() {
        let root = temp_root("cryptool-pqc-der-format-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "der", &pw, KeyFormat::Der);

        for path in [
            &keys.kem_public,
            &keys.dsa_public,
            &keys.kem_secret,
            &keys.dsa_secret,
        ] {
            let bytes = fs::read(path).unwrap();
            assert!(!bytes.starts_with(b"-----BEGIN "));
        }

        assert_eq!(
            detect_public_key_kind(&fs::read(&keys.kem_public).unwrap()).unwrap(),
            KeyKind::KemPublic
        );
        assert_eq!(
            detect_public_key_kind(&fs::read(&keys.dsa_public).unwrap()).unwrap(),
            KeyKind::DsaPublic
        );

        load_public_key(&keys.kem_public).unwrap();
        load_verifying_key(&keys.dsa_public).unwrap();
        load_kem_secret(&keys.kem_secret, &pw).unwrap();
        load_dsa_secret(&keys.dsa_secret, &pw).unwrap();

        encrypt_decrypt_file(&root, &keys, &pw);
        sign_verify_file(&root, &keys, &pw);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_kind_is_rejected() {
        let root = temp_root("cryptool-pqc-wrong-kind-test");
        let pw = SecretString::new("testpw".to_owned());
        let keys = generate(&root, "pem", &pw, KeyFormat::Pem);

        // ML-DSA ist kein KEM-Schlüssel usw.
        assert!(load_public_key(&keys.dsa_public).is_err());
        assert!(load_verifying_key(&keys.kem_public).is_err());
        assert!(load_kem_secret(&keys.dsa_secret, &pw).is_err());
        assert!(load_dsa_secret(&keys.kem_secret, &pw).is_err());

        // Auch die Dateiendungen werden nicht blind vertraut: eine umbenannte
        // ML-DSA-Datei bleibt ein ML-DSA-Schlüssel.
        let renamed = root.join("vertauscht-kem.pub.pem");
        fs::copy(&keys.dsa_public, &renamed).unwrap();
        assert_eq!(
            detect_public_key_kind(&fs::read(&renamed).unwrap()).unwrap(),
            KeyKind::DsaPublic
        );
        assert!(load_public_key(&renamed).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unencrypted_pkcs8_import_is_accepted() {
        let root = temp_root("cryptool-pqc-plain-pkcs8-test");
        let signing_key = MlDsaSigningKey::<MlDsa65>::generate();
        let document = signing_key.to_pkcs8_der().unwrap();
        let pem = document.to_pem("PRIVATE KEY", LineEnding::LF).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let path = root.join("dsa.sec.pem");
        fs::write(&path, pem.as_bytes()).unwrap();

        let pw = SecretString::new("beliebig".to_owned());
        load_dsa_secret(&path, &pw).unwrap();
        load_kem_secret(&path, &pw).unwrap_err();

        let _ = fs::remove_dir_all(&root);
    }
}
