//! OpenPGP-Modus (RFC 9580) auf Basis von rPGP.
//!
//! Funktionsumfang:
//! - Schlüsselfpaar erzeugen (v6: Ed25519-Primärschlüssel + X25519-Verschlüsselungs-Unterschlüssel),
//!   exportiert als ASCII-Armor (`.sec.asc` / `.pub.asc`).
//! - Dateien und Ordner für einen Empfänger verschlüsseln (binär oder ASCII-Armor).
//! - Nachrichten mit dem eigenen geheimen Schlüssel entschlüsseln.
//!
//! Ordner werden wie beim CTX-Modus als zstd-komprimiertes tar-Archiv als
//! Klartextquelle gestreamt; vor den tar+zstd-Stream wird eine feste Kennung
//! (`cryptool-tar\n`) geschrieben, damit beim Entschlüsseln Ordner von
//! einzelnen Dateien unterschieden werden können. Das ist nötig, weil rPGP
//! den Literal-Dateinamen in SEIPD-Nachrichten grundsätzlich leer schreibt.
//! Verschlüsselt wird nach RFC 9580 mit SEIPD v2 (AEAD) unter AES-256 und OCB.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

use pgp::composed::{
    ArmorOptions, Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;
use zeroize::Zeroize;

use crate::engine::{
    self, part_path, scan_dir, with_part_dir, with_part_file, Error, Progress, Report, Result,
    Tracker,
};
use crate::{ExposeSecret, SecretString};

/// Standard-Dateierweiterung für binäre PGP-Nachrichten.
pub const EXTENSION: &str = "pgp";
/// Dateierweiterung für ASCII-Armor-Ausgaben.
pub const ARMOR_EXTENSION: &str = "asc";

const ZSTD_LEVEL: i32 = 3;
const NAME_SUFFIX_ARCHIVE: &str = ".tar.zst";
const PIPE_LIMIT: usize = 4 * 1024 * 1024;
const PIPE_POLL: Duration = Duration::from_millis(200);

/// Kennung am Anfang des Klartexts von Ordner-Nachrichten. rPGP 0.21 schreibt
/// den Literal-Dateinamen grundsätzlich leer (siehe `to_writer_inner`), daher
/// markieren wir Archive direkt im Klartext.
const SRC_PLAIN_MAGIC: &[u8] = b"cryptool-tar\n";

// -------------------------------------------------------------------- Fehler

/// Kurzschreibweise für rPGP-Fehler als `Error::Pgp`.
fn pgp_err(e: impl std::fmt::Display) -> Error {
    Error::Pgp(e.to_string())
}

fn io_other(msg: &str) -> io::Error {
    io::Error::other(msg.to_owned())
}

fn file_name_of(input: &Path) -> String {
    input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "datei".to_owned())
}

// --------------------------------------------------------------- Schlüssel

fn to_password(pass: &str) -> Password {
    Password::from(pass)
}

/// Lädt einen öffentlichen Empfängerschlüssel (Armor oder binär).
pub(crate) fn load_public_key(path: &Path) -> Result<SignedPublicKey> {
    let bytes = fs::read(path)?;
    let (key, _headers) = SignedPublicKey::from_reader_single(&bytes[..]).map_err(pgp_err)?;
    key.verify_bindings()
        .map_err(|e| Error::Pgp(format!("Schlüssel ungültig (Selbstsignaturen): {e}")))?;
    Ok(key)
}

/// Lädt einen geheimen Schlüssel (Armor oder binär).
pub(crate) fn load_secret_key(path: &Path) -> Result<SignedSecretKey> {
    let bytes = fs::read(path)?;
    let (key, _headers) = SignedSecretKey::from_reader_single(&bytes[..]).map_err(pgp_err)?;
    key.verify_bindings()
        .map_err(|e| Error::Pgp(format!("Schlüssel ungültig (Selbstsignaturen): {e}")))?;
    Ok(key)
}

/// Wählt den Verschlüsselungs-Unterschlüssel (erster, der verschlüsseln darf).
fn pick_encryption_key(key: &SignedPublicKey) -> Result<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .find(|k| k.algorithm().can_encrypt())
        .ok_or_else(|| {
            Error::Pgp(
                "Der Schlüssel enthält keinen Unterschlüssel mit Verschlüsselungsfähigkeit".into(),
            )
        })
}

/// Erzeugt ein geheim/öffentliches Schlüsselfpaar und schreibt beide als
/// ASCII-Armor in `secret_out` bzw. `public_out`.
pub fn generate_key(
    user_id: &str,
    passphrase: SecretString,
    secret_out: &Path,
    public_out: &Path,
    force: bool,
) -> Result<()> {
    for out in [secret_out, public_out] {
        if out.exists() && !force {
            return Err(Error::OutputExists(out.to_path_buf()));
        }
    }

    let mut pw = passphrase.expose_secret().to_owned();

    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::None)
        .can_authenticate(false)
        .primary_user_id(user_id.to_string())
        .passphrase(Some(pw.clone()))
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::X25519)
            .can_sign(false)
            .can_authenticate(false)
            .can_encrypt(EncryptionCaps::All)
            .build()
            .map_err(|e| {
                Error::Pgp(format!("Unterschlüssel-Parameter: {e}"))
            })?]);
    let params = params.build().map_err(pgp_err)?;

    let secret = params
        .generate(thread_rng())
        .map_err(|e| Error::Pgp(format!("Schlüsselerzeugung fehlgeschlagen: {e}")))?;

    secret
        .verify_bindings()
        .map_err(|e| Error::Pgp(format!("Selbstsignaturen fehlerhaft: {e}")))?;
    // Das Klartext-Password wird nach der Schlüsselerzeugung nicht mehr
    // gebraucht und aus dem Speicher entfernt (bestmögliche Anstrengung).
    pw.zeroize();
    let public = secret.to_public_key();

    let sec_part = part_path(secret_out);
    {
        let w = &mut BufWriter::new(File::create(&sec_part)?);
        secret
            .to_armored_writer(w, ArmorOptions::default())
            .map_err(pgp_err)?;
    }
    fs::rename(&sec_part, secret_out)?;

    let pub_part = part_path(public_out);
    {
        let w = &mut BufWriter::new(File::create(&pub_part)?);
        public
            .to_armored_writer(w, ArmorOptions::default())
            .map_err(pgp_err)?;
    }
    fs::rename(&pub_part, public_out)?;
    Ok(())
}

// ------------------------------------------------------------------- Pipes

struct PipeState {
    buf: VecDeque<u8>,
    closed: bool,
    /// Falls gesetzt: Fehler, der beim Auslesen (nach dem Restpuffer) auftritt.
    err: Option<String>,
}

/// Begrenzter Puffer zwischen dem tar/zstd-Producer (Scoped-Thread) und dem
/// PGP-Writer. Das Abbruch-Flag wird in jeder Warteschleife berücksichtigt.
struct Pipe<'c> {
    state: Mutex<PipeState>,
    cv: Condvar,
    cancel: &'c AtomicBool,
}

impl<'c> Pipe<'c> {
    fn new(cancel: &'c AtomicBool) -> Self {
        Self {
            state: Mutex::new(PipeState {
                buf: VecDeque::new(),
                closed: false,
                err: None,
            }),
            cv: Condvar::new(),
            cancel,
        }
    }

    fn check_cancel(&self) -> io::Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        Ok(())
    }

    /// Blockierend alle Daten in den Puffer schreiben (maximal `PIPE_LIMIT`).
    fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.state.lock().expect("pipe mutex");
        while !data.is_empty() {
            self.check_cancel()?;
            while state.buf.len() >= PIPE_LIMIT && state.err.is_none() && !state.closed {
                state = self.cv.wait_timeout(state, PIPE_POLL).expect("pipe wait").0;
                self.check_cancel()?;
            }
            if let Some(err) = &state.err {
                return Err(io_other(err.as_str()));
            }
            if state.closed {
                return Err(io_other("Empfänger hat die Pipe geschlossen"));
            }
            let take = data.len().min(PIPE_LIMIT - state.buf.len());
            state.buf.extend(data[..take].iter().copied());
            self.cv.notify_all();
            data = &data[take..];
        }
        Ok(())
    }

    /// Liest bis zu `out.len()` Bytes; blockiert, bis Daten oder Ende kommen.
    fn read(&self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().expect("pipe mutex");
        loop {
            if !state.buf.is_empty() {
                let n = out.len().min(state.buf.len());
                for (i, b) in state.buf.iter().take(n).copied().enumerate() {
                    out[i] = b;
                }
                state.buf.drain(..n);
                self.cv.notify_all();
                return Ok(n);
            }
            if state.closed {
                if let Some(err) = &state.err {
                    return Err(io_other(err.as_str()));
                }
                return Ok(0);
            }
            self.check_cancel()?;
            state = self.cv.wait_timeout(state, PIPE_POLL).expect("pipe wait").0;
        }
    }

    /// Schließt das Schreibende; ein Fehler wird vom Leser gemeldet, sobald
    /// alle Bytes verbraucht sind.
    fn close(&self, err: Option<String>) {
        let mut state = self.state.lock().expect("pipe mutex");
        if state.err.is_none() {
            state.err = err;
        }
        state.closed = true;
        self.cv.notify_all();
    }
}

impl Pipe<'_> {
    /// Lässt einen blockierenden Producer los (Leser-Seite ist beendet), ohne
    /// einen bereits vorhandenen Fehler zu überschreiben.
    fn close_broken(&self) {
        self.close(Some("Empfängerseite wurde vorzeitig beendet".into()));
    }
}

/// `Write`-Adapter auf die Pipe für den tar/zstd-Producer.
struct PipeWriter<'p, 'c> {
    pipe: &'p Pipe<'c>,
}

impl Write for PipeWriter<'_, '_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.pipe.write_all(data)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Zählt Original-Bytes für den Fortschritt und erlaubt Abbruch.
struct PumpCounter<'a> {
    inner: File,
    count: &'a AtomicU64,
    cancel: &'a AtomicBool,
}

impl Read for PumpCounter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.count.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(n)
    }
}

/// Baut tar+zstd aus einem `DirPlan` in eine Pipe. Rückgabe ohne Seiteneffekte
/// auf die Pipe: bei Fehler wird der Leser über die Pipe benachrichtigt.
fn pump_dir(
    plan: &engine::DirPlan,
    pipe: &Pipe<'_>,
    count: &AtomicU64,
    cancel: &AtomicBool,
) -> Result<()> {
    let res = (|| -> Result<()> {
        let mut writer = PipeWriter { pipe };
        // Kennung zuerst, damit der Empfänger Ordner von Dateien unterscheiden kann.
        writer.write_all(SRC_PLAIN_MAGIC)?;
        let zenc = zstd::Encoder::new(writer, ZSTD_LEVEL)?;
        let mut builder = tar::Builder::new(zenc);

        for entry in plan.entries() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Canceled);
            }
            let mut h = tar::Header::new_gnu();
            if entry.is_dir() {
                let m = fs::metadata(entry.path())?;
                h.set_metadata_in_mode(&m, tar::HeaderMode::Complete);
                h.set_uid(0);
                h.set_gid(0);
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                builder.append_data(&mut h, entry.name(), io::empty())?;
            } else {
                let f = File::open(entry.path())?;
                let m = f.metadata()?;
                h.set_metadata_in_mode(&m, tar::HeaderMode::Complete);
                h.set_uid(0);
                h.set_gid(0);
                builder.append_data(
                    &mut h,
                    entry.name(),
                    PumpCounter {
                        inner: f,
                        count,
                        cancel,
                    },
                )?;
            }
        }

        let zenc = builder.into_inner()?;
        zenc.finish()?;
        Ok(())
    })();
    match res {
        Err(e) => {
            pipe.close(Some(match &e {
                Error::Canceled => "abgebrochen".to_owned(),
                Error::Io(io_err) => format!("E/A-Fehler: {io_err}"),
                other => other.to_string(),
            }));
            Err(e)
        }
        Ok(()) => {
            pipe.close(None);
            Ok(())
        }
    }
}

// ------------------------------------------------------------- Fortschritt

/// Klartextquelle einer einzelnen Datei (Progress + Abbruch).
struct FileSource<'a> {
    inner: File,
    tracker: Tracker<'a>,
    cancel: &'a AtomicBool,
}

impl Read for FileSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tracker.add(n as u64);
        }
        Ok(n)
    }
}

/// Klartextquelle für Ordner: liest tar+zstd aus der Pipe und meldet den
/// Fortschritt (Original-Bytes) an den Tracker.
struct DirSource<'a> {
    pipe: &'a Pipe<'a>,
    count: &'a AtomicU64,
    seen: u64,
    tracker: Tracker<'a>,
    cancel: &'a AtomicBool,
}

impl Read for DirSource<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        let n = self.pipe.read(out)?;
        let done = self.count.load(Ordering::Relaxed);
        if done > self.seen {
            self.tracker.add(done - self.seen);
            self.seen = done;
        }
        Ok(n)
    }
}

/// Lesessor für entschlüsselte Daten (Progress + Abbruch).
struct TrackRead<'a, R> {
    inner: R,
    tracker: Tracker<'a>,
    cancel: &'a AtomicBool,
}

// ------------------------------------------------- Ordner-Kennung erkennen

enum MagicState {
    /// Sammelt die ersten Bytes bis zur Entscheidung.
    Checking(Vec<u8>),
    /// Kennung passt: tar+zstd-Archiv, Kennung ist bereits verbraucht.
    Archive,
    /// Keine Kennung: reguläre Datei; `Bytes` sind bereits gelesen und müssen
    /// zuerst ausgeliefert werden.
    Plain(Vec<u8>),
}

impl MagicState {
    fn is_archive(&self) -> bool {
        matches!(self, MagicState::Archive)
    }
}

/// Entschlüsselter Datenstrom, der die `SRC_PLAIN_MAGIC`-Kennung auswertet.
/// Während der Prüfung werden alle Bytes gepuffert und im Klartextfall
/// vollständig weitergereicht (auch bei kürzeren Dateien als der Kennung).
struct MagicReader<R> {
    inner: R,
    state: MagicState,
}

impl<R: Read> MagicReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: MagicState::Checking(Vec::new()),
        }
    }

    /// Liest vorausschauend bis zur Entscheidung. Danach ist der Reader
    /// automatisch so geschaltet, dass alle gesehenen Bytes vollständig
    /// auskommen.
    fn resolve(&mut self) -> io::Result<bool> {
        while matches!(self.state, MagicState::Checking(_)) {
            self.pump_magic()?;
        }
        Ok(self.state.is_archive())
    }

    fn pump_magic(&mut self) -> io::Result<()> {
        let MagicState::Checking(accum) = &mut self.state else {
            return Ok(());
        };
        let have = accum.len();
        if have >= SRC_PLAIN_MAGIC.len() {
            return Ok(());
        }
        let mut tmp = [0u8; 32];
        let n = self.inner.read(&mut tmp[..SRC_PLAIN_MAGIC.len() - have])?;
        if n > 0 {
            accum.extend_from_slice(&tmp[..n]);
        }
        if accum.len() == SRC_PLAIN_MAGIC.len() {
            let bytes = std::mem::take(accum);
            self.state = if bytes == SRC_PLAIN_MAGIC {
                MagicState::Archive
            } else {
                MagicState::Plain(bytes)
            };
        } else if n == 0 {
            // Ende des Klartexts vor der vollen Kennung: reguläre Datei.
            let bytes = std::mem::take(accum);
            self.state = MagicState::Plain(bytes);
        }
        Ok(())
    }
}

impl<R: Read> Read for MagicReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if matches!(self.state, MagicState::Checking(_)) {
            self.resolve()?;
        }
        match &mut self.state {
            MagicState::Checking(_) => unreachable!("zustand wird vorher aufgelöst"),
            MagicState::Archive => self.inner.read(out),
            MagicState::Plain(pending) => {
                if pending.is_empty() {
                    return self.inner.read(out);
                }
                let n = out.len().min(pending.len());
                out[..n].copy_from_slice(&pending[..n]);
                pending.drain(..n);
                Ok(n)
            }
        }
    }
}

impl<R: Read> Read for TrackRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io_other("abgebrochen"));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tracker.add(n as u64);
        }
        Ok(n)
    }
}

// ------------------------------------------------------- Verschlüsseln

fn finish_encrypt<R: Read>(
    literal_name: String,
    source: R,
    subkey: &SignedPublicSubKey,
    armor: bool,
    w: &mut BufWriter<File>,
) -> Result<()> {
    let mut builder = MessageBuilder::from_reader(literal_name, source).seipd_v2(
        thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
    );
    builder
        .encrypt_to_key(thread_rng(), subkey)
        .map_err(pgp_err)?;
    if armor {
        builder
            .to_armored_writer(thread_rng(), ArmorOptions::default(), w)
            .map_err(pgp_err)?;
    } else {
        builder.to_writer(thread_rng(), w).map_err(pgp_err)?;
    }
    Ok(())
}

/// Ordner-Eingabe: tar+zstd im Scoped-Thread produziert, der PGP-Writer liest
/// aus der Pipe. Beide Seiten teilen sich Abbruch und Fehlersignalisierung.
#[allow(clippy::too_many_arguments)]
fn encrypt_dir(
    plan: &engine::DirPlan,
    literal_name: &str,
    subkey: &SignedPublicSubKey,
    armor: bool,
    w: &mut BufWriter<File>,
    total: u64,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<()> {
    let pipe = Pipe::new(cancel);
    let count = AtomicU64::new(0);

    thread::scope(|scope| {
        let pump = scope.spawn(|| pump_dir(plan, &pipe, &count, cancel));

        let src = DirSource {
            pipe: &pipe,
            count: &count,
            seen: 0,
            tracker: Tracker::new(0, total, on_progress),
            cancel,
        };

        let res = finish_encrypt(literal_name.to_owned(), src, subkey, armor, w);
        if res.is_err() {
            pipe.close_broken();
        }
        let pump_res = pump.join().expect("pump thread panicked");

        match pump_res {
            Err(e) => Err(e),
            Ok(()) => res,
        }
    })
}

/// Verschlüsselt eine Datei oder einen Ordner für einen Empfänger.
///
/// Bei Ordnern wird tar+zstd als Klartextquelle gestreamt; der Literal-Name
/// endet auf `.tar.zst`.
pub fn encrypt_path(
    input: &Path,
    output: &Path,
    recipient_key_file: &Path,
    armor: bool,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<Report> {
    let public = load_public_key(recipient_key_file)?;
    let subkey = pick_encryption_key(&public)?;

    let meta = fs::metadata(input)?;
    let plan = if meta.is_dir() {
        Some(scan_dir(input, output)?)
    } else {
        None
    };
    let total = plan.as_ref().map_or(meta.len(), engine::DirPlan::total);
    let skipped = plan.as_ref().map_or(0, engine::DirPlan::skipped);

    let literal_name = if plan.is_some() {
        format!("{}{NAME_SUFFIX_ARCHIVE}", file_name_of(input))
    } else {
        file_name_of(input)
    };

    let res = with_part_file(output, force, move |w| match &plan {
        Some(plan) => encrypt_dir(
            plan,
            &literal_name,
            subkey,
            armor,
            w,
            total,
            on_progress,
            cancel,
        ),
        None => {
            let src = FileSource {
                inner: File::open(input)?,
                tracker: Tracker::new(0, total, on_progress),
                cancel,
            };
            finish_encrypt(literal_name, src, subkey, armor, w)
        }
    });
    match res {
        Ok(()) => Ok(Report { skipped }),
        Err(_) if cancel.load(Ordering::Relaxed) => Err(Error::Canceled),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------ Entschlüsseln

/// Entschlüsselt eine PGP-Nachricht. Bei Ordner-Eingaben (Literal-Name
/// `.tar.zst`) ist `output` der neue Ordner, sonst die Zieldatei.
pub fn decrypt_path(
    input: &Path,
    output: &Path,
    secret_key_file: &Path,
    passphrase: SecretString,
    force: bool,
    on_progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<()> {
    let secret = load_secret_key(secret_key_file)?;
    let pw = to_password(passphrase.expose_secret());

    let file = File::open(input)?;
    let reader = BufReader::new(file);
    let (msg, _armor_headers) = Message::from_reader(reader).map_err(pgp_err)?;
    if !msg.is_encrypted() {
        return Err(Error::Invalid(
            "Die Nachricht enthält keine Verschlüsselung".into(),
        ));
    }
    let mut msg = msg
        .decrypt(&pw, &secret)
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    if msg.is_compressed() {
        msg = msg.decompress().map_err(pgp_err)?;
    }
    let tracker = Tracker::new(0, 0, on_progress);
    // Archiv-Erkennung: Kurzes Aufschnappen der Kennung am Klartextanfang;
    // danach laufen alle Bytes (inklusive der bereits gelesenen) durch.
    let mut sniff = MagicReader::new(TrackRead {
        inner: msg,
        tracker,
        cancel,
    });
    let is_archive = sniff.resolve()?;

    let res = if is_archive {
        with_part_dir(output, move |part| engine::extract_archive(sniff, part))
    } else {
        with_part_file(output, force, move |w| {
            io::copy(&mut sniff, w)?;
            Ok(())
        })
    };

    match res {
        Err(_) if cancel.load(Ordering::Relaxed) => Err(Error::Canceled),
        res => res,
    }
}

/// Verschlüsselt UTF-8-Text als OpenPGP-Nachricht im ASCII-Armor-Format.
pub fn encrypt_text(text: &str, recipient_key_file: &Path) -> Result<String> {
    let public = load_public_key(recipient_key_file)?;
    let subkey = pick_encryption_key(&public)?;
    let mut builder = MessageBuilder::from_bytes("message.txt", text.as_bytes().to_vec()).seipd_v2(
        thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
    );
    builder
        .encrypt_to_key(thread_rng(), subkey)
        .map_err(pgp_err)?;
    let mut armored = Vec::new();
    builder
        .to_armored_writer(thread_rng(), ArmorOptions::default(), &mut armored)
        .map_err(pgp_err)?;
    String::from_utf8(armored).map_err(pgp_err)
}

/// Entschlüsselt OpenPGP-ASCII-Armor zu UTF-8-Text.
pub fn decrypt_text(
    armored: &str,
    secret_key_file: &Path,
    passphrase: SecretString,
) -> Result<String> {
    let secret = load_secret_key(secret_key_file)?;
    let (msg, _) = Message::from_reader(Cursor::new(armored.as_bytes())).map_err(pgp_err)?;
    if !msg.is_encrypted() {
        return Err(Error::Invalid(
            "Die Nachricht enthält keine Verschlüsselung".into(),
        ));
    }
    let mut msg = msg
        .decrypt(&to_password(passphrase.expose_secret()), &secret)
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    if msg.is_compressed() {
        msg = msg.decompress().map_err(pgp_err)?;
    }
    let data = msg.as_data_vec().map_err(pgp_err)?;
    String::from_utf8(data)
        .map_err(|_| Error::Invalid("Der entschlüsselte Inhalt ist kein UTF-8-Text".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretString;

    fn no_progress() -> impl FnMut(Progress) {
        |_p: Progress| {}
    }

    /// Ganz standard: Datei- und Ordner-Rundreise über die öffentliche API.
    #[test]
    fn file_and_dir_roundtrip() {
        let root = std::env::temp_dir().join("cryptool-pgp-rtrip-test");
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"HALLO WELT").unwrap();
        fs::write(src.join("sub").join("b.txt"), b"UNTERORDNER").unwrap();
        // Eine gewöhnliche Datei, die atomic "tar.zst heißt: darf beim
        // Entschlüsseln NIEMALS als Ordner behandelt werden.
        fs::write(src.parent().unwrap().join("x.tar.zst"), b"kein archiv").unwrap();

        let secret_out = root.join("s.sec.asc");
        let public_out = root.join("p.pub.asc");
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

        // Datei: hinein -> PGP -> zurück
        let file_enc = root.join("x.tar.zst.pgp");
        encrypt_path(
            &root.join("x.tar.zst"),
            &file_enc,
            &public_out,
            false,
            true,
            &mut no_progress(),
            &cancel,
        )
        .unwrap();
        let file_ret = root.join("x.tar.zst.ret");
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
        assert_eq!(fs::read(&file_ret).unwrap(), b"kein archiv");

        // Ordner: hinein -> PGP -> zurück
        let dir_enc = root.join("src.pgp");
        encrypt_path(
            &src,
            &dir_enc,
            &public_out,
            false,
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
            pw,
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

        let _ = fs::remove_dir_all(&root);
    }
}
