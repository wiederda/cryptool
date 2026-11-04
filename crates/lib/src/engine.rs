//! Implementierung des bestehenden CTX-Dateiformats und der Dateioperationen.
//!
//! Format (alle Zahlen little-endian), Header = 59 Bytes:
//!
//! ```text
//!  0..4   Magic "CTXF"
//!  4      Version (1)
//!  5      Cipher-ID (1 = XChaCha20-Poly1305)
//!  6      KDF-ID (1 = Argon2id)
//!  7      Flags: 0 = einzelne Datei, 3 = Ordner (tar + zstd)
//!  8..12  Argon2 m_cost (KiB)
//! 12..16  Argon2 t_cost
//! 16..20  Argon2 parallelism
//! 20..24  Chunk-Größe (Klartext, Bytes)
//! 24..40  Salt (16 Bytes)
//! 40..59  Nonce-Präfix für STREAM (19 Bytes)
//! ```
//!
//! Danach folgen die Chunks (je Klartext-Chunk + 16 Byte Tag). Der Header ist als
//! AAD an jeden Chunk gebunden, wird also mit authentifiziert. Der letzte Chunk ist
//! immer kürzer als ein voller Chunk (ggf. nur der Tag), dadurch wird auch
//! Abschneiden der Datei erkannt.
//!
//! Bei Ordnern ist der Klartext ein zstd-komprimiertes tar-Archiv. Dateinamen und
//! Struktur stehen also nur im verschlüsselten Teil.

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{OsRng, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

pub use cryptool_core::{ExposeSecret, SecretString};

// ---------------------------------------------------------------- Konstanten

pub const EXTENSION: &str = "ctx";
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024; // 1 MiB

const MAGIC: &[u8; 4] = b"CTXF";
const VERSION: u8 = 1;
const CIPHER_XCHACHA20POLY1305: u8 = 1;
const KDF_ARGON2ID: u8 = 1;

const FLAG_TAR: u8 = 0b01;
const FLAG_ZSTD: u8 = 0b10;
const ZSTD_LEVEL: i32 = 3;

pub const HEADER_LEN: usize = 59;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 19; // 24 (XChaCha) - 5 (STREAM BE32)
pub(crate) const TAG_LEN: usize = 16;

// Standard-Parameter beim Verschlüsseln (stehen im Header, sind also änderbar)
const KDF_M_KIB: u32 = 64 * 1024; // 64 MiB
const KDF_T: u32 = 3;
const KDF_P: u32 = 1;

// Obergrenzen beim Entschlüsseln (Schutz vor bösartigen Headern)
const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T: u32 = 10;
const MAX_P: u32 = 16;
const MIN_CHUNK: u32 = 1024;
const MAX_CHUNK: u32 = 64 * 1024 * 1024;

pub(crate) type Enc = EncryptorBE32<XChaCha20Poly1305>;
pub(crate) type Dec = DecryptorBE32<XChaCha20Poly1305>;

// -------------------------------------------------------------------- Fehler

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("E/A-Fehler: {0}")]
    Io(#[from] io::Error),
    #[error("keine gültige cryptool-Datei")]
    NotCryptoolFile,
    #[error("nicht unterstützte Dateiversion oder Algorithmen (Version {0})")]
    Unsupported(u8),
    #[error("ungültige Parameter im Header")]
    BadHeader,
    #[error("falsches Passwort oder beschädigte Datei")]
    WrongPasswordOrCorrupt,
    #[error("Datei ist beschädigt oder abgeschnitten")]
    Corrupt,
    #[error("Schlüsselableitung fehlgeschlagen: {0}")]
    Kdf(String),
    #[error("Verschlüsselungsfehler")]
    Crypto,
    #[error("Ziel existiert bereits: {0}")]
    OutputExists(PathBuf),
    #[error("{0}")]
    Invalid(String),
    #[error("OpenPGP-Fehler: {0}")]
    Pgp(String),
    #[error("Signatur ist ungültig")]
    SignatureInvalid,
    #[error("abgebrochen")]
    Canceled,
}

// ------------------------------------------------------------------- Header

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub cipher: u8,
    pub kdf: u8,
    pub flags: u8,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub chunk_size: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn generate(flags: u8) -> Self {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        Self {
            version: VERSION,
            cipher: CIPHER_XCHACHA20POLY1305,
            kdf: KDF_ARGON2ID,
            flags,
            m_kib: KDF_M_KIB,
            t: KDF_T,
            p: KDF_P,
            chunk_size: DEFAULT_CHUNK_SIZE,
            salt,
            nonce,
        }
    }

    /// `true`, wenn der Inhalt ein Ordner (tar + zstd) ist, sonst eine einzelne Datei.
    pub fn is_dir(&self) -> bool {
        self.flags & FLAG_TAR != 0
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(MAGIC);
        b[4] = self.version;
        b[5] = self.cipher;
        b[6] = self.kdf;
        b[7] = self.flags;
        b[8..12].copy_from_slice(&self.m_kib.to_le_bytes());
        b[12..16].copy_from_slice(&self.t.to_le_bytes());
        b[16..20].copy_from_slice(&self.p.to_le_bytes());
        b[20..24].copy_from_slice(&self.chunk_size.to_le_bytes());
        b[24..40].copy_from_slice(&self.salt);
        b[40..59].copy_from_slice(&self.nonce);
        b
    }

    fn from_bytes(b: &[u8; HEADER_LEN]) -> Result<Self> {
        if &b[0..4] != MAGIC {
            return Err(Error::NotCryptoolFile);
        }
        let version = b[4];
        let flags = b[7];
        if version != VERSION
            || b[5] != CIPHER_XCHACHA20POLY1305
            || b[6] != KDF_ARGON2ID
            || !(flags == 0 || flags == FLAG_TAR | FLAG_ZSTD)
        {
            return Err(Error::Unsupported(version));
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let h = Self {
            version,
            cipher: b[5],
            kdf: b[6],
            flags,
            m_kib: u32_at(8),
            t: u32_at(12),
            p: u32_at(16),
            chunk_size: u32_at(20),
            salt: b[24..40].try_into().unwrap(),
            nonce: b[40..59].try_into().unwrap(),
        };
        let ok = (1..=MAX_M_KIB).contains(&h.m_kib)
            && (1..=MAX_T).contains(&h.t)
            && (1..=MAX_P).contains(&h.p)
            && (MIN_CHUNK..=MAX_CHUNK).contains(&h.chunk_size);
        if !ok {
            return Err(Error::BadHeader);
        }
        Ok(h)
    }
}

/// Liest nur den Header (ohne Passwort), z. B. für `inspect`.
pub fn read_header(path: &Path) -> Result<Header> {
    let mut f = File::open(path)?;
    read_header_from(&mut f).map(|(h, _)| h)
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

// ------------------------------------------------------- Fortschritt / Ergebnis

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
}

/// Ergebnis von `encrypt_path`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Report {
    /// Symlinks und Sonderdateien in Ordnern, die nicht aufgenommen wurden.
    pub skipped: u64,
}

/// Ergebnis einer erfolgreichen Signaturprüfung.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Nutzerkennung des Unterzeichners.
    pub signer: String,
    /// Fingerprint bzw. Schlüsselkennung des verwendeten Schlüssels (Hex).
    pub key_id: String,
    /// Signaturzeitpunkt als Unix-Sekunden, falls im Format enthalten.
    pub created: Option<u64>,
}

pub(crate) struct Tracker<'a> {
    done: u64,
    total: u64,
    cb: &'a mut dyn FnMut(Progress),
}

impl<'a> Tracker<'a> {
    pub(crate) fn new(done: u64, total: u64, cb: &'a mut dyn FnMut(Progress)) -> Self {
        Self { done, total, cb }
    }
    pub(crate) fn add(&mut self, n: u64) {
        self.done += n;
        (self.cb)(Progress {
            done: self.done,
            total: self.total,
        });
    }
}

// --------------------------------------------------------------- Hilfsfunktionen

/// Leitet den Schlüssel ab. Das Passwort wird hier übernommen und am Ende der
/// Funktion gelöscht (Zeroize beim Drop) -- es lebt also nur so lange wie nötig.
fn derive_key(password: SecretString, h: &Header) -> Result<Zeroizing<[u8; 32]>> {
    cryptool_core::derive_key(password.expose_secret(), &h.salt, h.m_kib, h.t, h.p)
        .map_err(Error::Kdf)
}

fn cipher_from(key: &Zeroizing<[u8; 32]>) -> XChaCha20Poly1305 {
    cryptool_core::xchacha20poly1305(key)
}

/// Liest, bis der Puffer voll oder die Datei zu Ende ist.
pub(crate) fn fill(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub(crate) fn part_path(output: &Path) -> PathBuf {
    let mut s = output.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

fn io_other(msg: &str) -> io::Error {
    io::Error::other(msg.to_owned())
}

/// Schreibt in `<ziel>.part` und benennt erst bei Erfolg um. Bei Fehler oder
/// Abbruch wird die Teildatei gelöscht.
pub(crate) fn with_part_file<F>(output: &Path, force: bool, f: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    if output.exists() && !force {
        return Err(Error::OutputExists(output.to_path_buf()));
    }
    let part = part_path(output);
    let mut w = BufWriter::new(File::create(&part)?);
    let res = (|| -> Result<()> {
        f(&mut w)?;
        w.flush()?;
        w.get_ref().sync_all()?;
        Ok(())
    })();
    drop(w);
    match res {
        Ok(()) => {
            fs::rename(&part, output)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Wie `with_part_file`, aber für einen Ordner. Vorhandene Ordner werden nie
/// überschrieben.
pub(crate) fn with_part_dir<F>(output: &Path, f: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    if output.exists() {
        return Err(Error::OutputExists(output.to_path_buf()));
    }
    let part = part_path(output);
    if part.exists() {
        return Err(Error::OutputExists(part));
    }
    fs::create_dir(&part)?;
    match f(&part) {
        Ok(()) => {
            fs::rename(&part, output)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&part);
            Err(e)
        }
    }
}

// --------------------------------------------------- Verschlüsselnder Writer

/// `Write`-Senke: sammelt Klartext in Chunks und schreibt sie verschlüsselt weiter.
/// Ein voller Chunk wird erst geschrieben, wenn weitere Daten folgen; `finish`
/// schreibt den (kürzeren, ggf. leeren) letzten Chunk.
pub(crate) struct EncryptWriter<'a, W: Write> {
    inner: W,
    enc: Option<Enc>,
    aad: Vec<u8>,
    buf: Zeroizing<Vec<u8>>,
    chunk: usize,
    cancel: &'a AtomicBool,
}

impl<'a, W: Write> EncryptWriter<'a, W> {
    pub(crate) fn new(
        inner: W,
        enc: Enc,
        aad: Vec<u8>,
        chunk: usize,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self {
            inner,
            enc: Some(enc),
            aad,
            buf: Zeroizing::new(Vec::with_capacity(chunk)),
            chunk,
            cancel,
        }
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        let ct = self
            .enc
            .as_mut()
            .expect("encryptor")
            .encrypt_next(Payload {
                msg: self.buf.as_slice(),
                aad: &self.aad,
            })
            .map_err(|_| io_other("crypto"))?;
        self.inner.write_all(&ct)?;
        self.buf.zeroize();
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        if self.buf.len() == self.chunk {
            self.flush_chunk()?;
        }
        let ct = self
            .enc
            .take()
            .expect("encryptor")
            .encrypt_last(Payload {
                msg: self.buf.as_slice(),
                aad: &self.aad,
            })
            .map_err(|_| io_other("crypto"))?;
        self.inner.write_all(&ct)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        if self.buf.len() == self.chunk {
            self.flush_chunk()?;
        }
        let take = (self.chunk - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ----------------------------------------------------- Entschlüsselnder Reader

#[derive(Clone, Copy)]
pub(crate) enum Fail {
    Auth { first_chunk: bool },
    Canceled,
}

/// `Read`-Quelle: liest verschlüsselte Chunks und liefert den Klartext.
pub(crate) struct DecryptReader<'a, R: Read> {
    inner: R,
    dec: Option<Dec>,
    aad: Vec<u8>,
    enc_chunk: usize,
    enc_buf: Vec<u8>,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
    idx: u64,
    finished: bool,
    cancel: &'a AtomicBool,
    tracker: Tracker<'a>,
    fail: Rc<Cell<Option<Fail>>>,
}

impl<'a, R: Read> DecryptReader<'a, R> {
    pub(crate) fn new(
        inner: R,
        dec: Dec,
        aad: Vec<u8>,
        chunk_size: usize,
        cancel: &'a AtomicBool,
        tracker: Tracker<'a>,
        fail: Rc<Cell<Option<Fail>>>,
    ) -> Self {
        let enc_chunk = chunk_size + TAG_LEN;
        Self {
            inner,
            dec: Some(dec),
            aad,
            enc_chunk,
            enc_buf: vec![0u8; enc_chunk],
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
            idx: 0,
            finished: false,
            cancel,
            tracker,
            fail,
        }
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            self.fail.set(Some(Fail::Canceled));
            return Err(io_other("abgebrochen"));
        }
        let n = fill(&mut self.inner, &mut self.enc_buf)?;
        let last = n < self.enc_chunk;
        let payload = Payload {
            msg: &self.enc_buf[..n],
            aad: &self.aad,
        };
        let res = if last {
            self.dec.take().expect("decryptor").decrypt_last(payload)
        } else {
            self.dec.as_mut().expect("decryptor").decrypt_next(payload)
        };
        match res {
            Ok(pt) => {
                self.plain = Zeroizing::new(pt);
                self.pos = 0;
                self.idx += 1;
                self.finished = last;
                self.tracker.add(n as u64);
                Ok(())
            }
            Err(_) => {
                // Schlägt schon der erste Chunk fehl, ist meist das Passwort falsch.
                self.fail.set(Some(Fail::Auth {
                    first_chunk: self.idx == 0,
                }));
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication failed",
                ))
            }
        }
    }
}

impl<R: Read> Read for DecryptReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.plain.len() {
            if self.finished {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub(crate) fn remap_error(e: Error, fail: &Cell<Option<Fail>>) -> Error {
    match fail.get() {
        Some(Fail::Auth { first_chunk: true }) => Error::WrongPasswordOrCorrupt,
        Some(Fail::Auth { first_chunk: false }) => Error::Corrupt,
        Some(Fail::Canceled) => Error::Canceled,
        None => match e {
            Error::Io(ioe) if ioe.kind() == io::ErrorKind::InvalidData => Error::Corrupt,
            other => other,
        },
    }
}

// ------------------------------------------------------------ Ordner einlesen

pub(crate) struct PlanEntry {
    path: PathBuf,
    name: PathBuf,
    is_dir: bool,
}

impl PlanEntry {
    pub(crate) fn is_dir(&self) -> bool {
        self.is_dir
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn name(&self) -> &Path {
        &self.name
    }
}

pub(crate) struct DirPlan {
    entries: Vec<PlanEntry>,
    total: u64,
    skipped: u64,
}

impl DirPlan {
    pub(crate) fn entries(&self) -> &[PlanEntry] {
        &self.entries
    }
    pub(crate) fn total(&self) -> u64 {
        self.total
    }
    pub(crate) fn skipped(&self) -> u64 {
        self.skipped
    }
}

pub(crate) fn scan_dir(input: &Path, output: &Path) -> Result<DirPlan> {
    let root = fs::canonicalize(input)?;
    let base = root
        .file_name()
        .map(PathBuf::from)
        .ok_or_else(|| Error::Invalid("Ordnername nicht ermittelbar".into()))?;

    // Die Zieldatei darf nicht im zu verschlüsselnden Ordner liegen.
    let out_abs = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    if let (Some(parent), Some(fname)) = (out_abs.parent(), out_abs.file_name()) {
        if let Ok(p) = fs::canonicalize(parent) {
            if p.join(fname).starts_with(&root) {
                return Err(Error::Invalid(
                    "Die Zieldatei darf nicht im zu verschlüsselnden Ordner liegen".into(),
                ));
            }
        }
    }

    let mut plan = DirPlan {
        entries: Vec::new(),
        total: 0,
        skipped: 0,
    };
    for e in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let e = e.map_err(io::Error::from)?;
        let rel = e
            .path()
            .strip_prefix(&root)
            .expect("walkdir liefert Pfade unter root");
        let name = if rel.as_os_str().is_empty() {
            base.clone()
        } else {
            base.join(rel)
        };
        let ft = e.file_type();
        if ft.is_dir() {
            plan.entries.push(PlanEntry {
                path: e.path().to_path_buf(),
                name,
                is_dir: true,
            });
        } else if ft.is_file() {
            plan.total += e.metadata().map_err(io::Error::from)?.len();
            plan.entries.push(PlanEntry {
                path: e.path().to_path_buf(),
                name,
                is_dir: false,
            });
        } else {
            plan.skipped += 1; // Symlinks, Sonderdateien
        }
    }
    Ok(plan)
}

struct CountingReader<'a, 'b> {
    inner: File,
    tracker: &'a mut Tracker<'b>,
}

impl Read for CountingReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tracker.add(n as u64);
        }
        Ok(n)
    }
}

// ------------------------------------------------------------------ Verschlüsseln

/// Verschlüsselt eine Datei oder einen Ordner mit einem Passwort.
pub fn encrypt_path(
    input: &Path,
    output: &Path,
    password: SecretString,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<Report> {
    let meta = fs::metadata(input)?;
    let plan = if meta.is_dir() {
        Some(scan_dir(input, output)?)
    } else {
        None
    };
    let total = plan.as_ref().map_or(meta.len(), |p| p.total);
    let flags = if plan.is_some() {
        FLAG_TAR | FLAG_ZSTD
    } else {
        0
    };

    let header = Header::generate(flags);
    let hb = header.to_bytes();
    let key = derive_key(password, &header)?; // Passwort ist ab hier weg
    let enc = Enc::from_aead(cipher_from(&key), GenericArray::from_slice(&header.nonce));
    drop(key); // Der Cipher hält die Schlüsselkopie; unsere Kopie wird gelöscht.

    let mut tracker = Tracker {
        done: 0,
        total,
        cb: on_progress,
    };
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
        Ok(()) => Ok(Report {
            skipped: plan.map_or(0, |p| p.skipped),
        }),
        Err(_) if cancel.load(Ordering::Relaxed) => Err(Error::Canceled),
        Err(e) => Err(e),
    }
}

pub(crate) fn write_file_stream<W: Write>(
    input: &Path,
    mut sink: EncryptWriter<'_, W>,
    tracker: &mut Tracker<'_>,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut reader = File::open(input)?;
    let mut buf = Zeroizing::new(vec![0u8; sink.chunk]);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Canceled);
        }
        let n = fill(&mut reader, &mut buf)?;
        sink.write_all(&buf[..n])?;
        tracker.add(n as u64);
        if n < buf.len() {
            break;
        }
    }
    sink.finish()?;
    Ok(())
}

pub(crate) fn write_dir_stream<W: Write>(
    plan: &DirPlan,
    sink: EncryptWriter<'_, W>,
    tracker: &mut Tracker<'_>,
    cancel: &AtomicBool,
) -> Result<()> {
    let zenc = zstd::Encoder::new(sink, ZSTD_LEVEL)?;
    let mut builder = tar::Builder::new(zenc);
    for e in &plan.entries {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Canceled);
        }
        let mut h = tar::Header::new_gnu();
        if e.is_dir {
            let m = fs::metadata(&e.path)?;
            h.set_metadata_in_mode(&m, tar::HeaderMode::Complete);
            h.set_uid(0);
            h.set_gid(0);
            h.set_entry_type(tar::EntryType::Directory);
            h.set_size(0);
            builder.append_data(&mut h, &e.name, io::empty())?;
        } else {
            let f = File::open(&e.path)?;
            let m = f.metadata()?;
            h.set_metadata_in_mode(&m, tar::HeaderMode::Complete);
            h.set_uid(0);
            h.set_gid(0);
            builder.append_data(
                &mut h,
                &e.name,
                CountingReader {
                    inner: f,
                    tracker: &mut *tracker,
                },
            )?;
        }
    }
    let zenc = builder.into_inner()?;
    let sink = zenc.finish()?;
    sink.finish()?;
    tracker.add(0);
    Ok(())
}

// ------------------------------------------------------------------ Entschlüsseln

/// Entschlüsselt eine mit `encrypt_path` erzeugte Datei. Bei Ordnern ist `output`
/// der neue Ordner (der Name des Originalordners wird nicht übernommen).
pub fn decrypt_path(
    input: &Path,
    output: &Path,
    password: SecretString,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<()> {
    let mut file = File::open(input)?;
    let file_len = file.metadata()?.len();
    let (header, hb) = read_header_from(&mut file)?;
    let total = file_len.saturating_sub(HEADER_LEN as u64);

    let key = derive_key(password, &header)?; // Passwort ist ab hier weg
    let dec = Dec::from_aead(cipher_from(&key), GenericArray::from_slice(&header.nonce));
    drop(key);

    let fail: Rc<Cell<Option<Fail>>> = Rc::new(Cell::new(None));
    let reader = DecryptReader::new(
        file,
        dec,
        hb.to_vec(),
        header.chunk_size as usize,
        cancel,
        Tracker {
            done: 0,
            total,
            cb: on_progress,
        },
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

pub(crate) fn extract_archive<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let zdec = zstd::Decoder::new(reader)?;
    let mut archive = tar::Archive::new(zdec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();

        // Erste Komponente (Ordnername) wegwerfen, der Rest darf nur aus normalen
        // Namen bestehen (kein "..", keine absoluten Pfade).
        let mut comps = path.components();
        if !matches!(comps.next(), Some(Component::Normal(_))) {
            return Err(Error::Corrupt);
        }
        let mut rel = PathBuf::new();
        for c in comps {
            match c {
                Component::Normal(p) => rel.push(p),
                Component::CurDir => {}
                _ => return Err(Error::Corrupt),
            }
        }
        let target = dest.join(&rel);

        match entry.header().entry_type() {
            tar::EntryType::Directory => fs::create_dir_all(&target)?,
            tar::EntryType::Regular => {
                if rel.as_os_str().is_empty() {
                    return Err(Error::Corrupt);
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&target)?;
            }
            _ => return Err(Error::Corrupt), // Symlinks usw. gibt es in unseren Archiven nicht
        }
    }

    // Den Rest des Streams lesen: erst damit wird der letzte Chunk geprüft
    // (Schutz gegen abgeschnittene Dateien).
    let mut rest = archive.into_inner().finish();
    io::copy(&mut rest, &mut io::sink())?;
    Ok(())
}
