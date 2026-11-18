#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use cryptool_lib::{
    decrypt_path, encrypt_path, pgp_decrypt_path, pgp_decrypt_text, pgp_encrypt_path,
    pgp_encrypt_text, pgp_generate_key, pgp_sign_path, pgp_verify_path, pqc_decrypt_path,
    pqc_decrypt_text, pqc_detect_public_key_kind, pqc_encrypt_path, pqc_encrypt_text,
    pqc_generate_key, pqc_sign_path, pqc_verify_path, PqcKeyFormat, PqcKeyKind, Progress,
    SecretString, VerifyReport,
};
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, PartialEq, Eq)]
enum RibbonTab {
    Start,
    Keys,
    Help,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Ctx,
    Pgp,
    Pqc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

impl Op {
    fn verb(self) -> &'static str {
        match self {
            Op::Encrypt => "verschlüsseln",
            Op::Decrypt => "entschlüsseln",
            Op::Sign => "signieren",
            Op::Verify => "prüfen",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Op::Encrypt => "Verschlüsseln",
            Op::Decrypt => "Entschlüsseln",
            Op::Sign => "Signieren",
            Op::Verify => "Signatur prüfen",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Op::Encrypt => "Jetzt verschlüsseln",
            Op::Decrypt => "Jetzt entschlüsseln",
            Op::Sign => "Jetzt signieren",
            Op::Verify => "Signatur prüfen",
        }
    }

    fn is_text_allowed(self) -> bool {
        matches!(self, Op::Encrypt | Op::Decrypt)
    }

    fn uses_secret_key(self) -> bool {
        matches!(self, Op::Decrypt | Op::Sign)
    }
}

impl Method {
    fn key_based(self) -> bool {
        !matches!(self, Method::Ctx)
    }

    fn label(self) -> &'static str {
        match self {
            Method::Ctx => "CTX",
            Method::Pgp => "OpenPGP",
            Method::Pqc => "PQC",
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Method::Ctx => "ctx",
            Method::Pgp => "pgp",
            Method::Pqc => "pqc",
        }
    }

    fn extension(self) -> &'static str {
        self.tag()
    }

    fn signature_extension(self) -> &'static str {
        match self {
            Method::Ctx => "sig",
            Method::Pgp => "sig",
            Method::Pqc => "pqc.sig",
        }
    }

    fn signature_armor_extension(self) -> &'static str {
        match self {
            Method::Ctx => "sig.asc",
            Method::Pgp => "sig.asc",
            Method::Pqc => "pqc.sig.asc",
        }
    }

    fn text_label(self) -> &'static str {
        match self {
            Method::Ctx => "Text",
            Method::Pgp => "OpenPGP-Text (ASCII-Armor)",
            Method::Pqc => "PQC-Text (ASCII-Armor)",
        }
    }
}

enum Event {
    Progress(Progress),
    Finished(Result<String, String>),
}

enum KeyserverEvent {
    Listed(Result<Vec<KeyserverEntry>, String>),
    Downloaded {
        label: String,
        result: Result<Vec<u8>, String>,
    },
    Uploaded(Result<String, String>),
}

#[derive(Clone)]
struct KeyserverEntry {
    id: u64,
    owner: String,
    filename: String,
    method: Option<Method>,
}

#[derive(Clone)]
struct RecipientKey {
    label: String,
    path: PathBuf,
    method: Method,
    kind: Option<PqcKeyKind>,
}

#[derive(Clone)]
struct SecretKey {
    label: String,
    path: PathBuf,
    method: Method,
    kind: Option<PqcKeyKind>,
}

/// Für eine PQC-Operation benötigte Schlüsselart. PGP-Schlüssel haben keine
/// Unterart und liefern `None`.
fn required_pqc_key_kind(method: Method, op: Op) -> Option<PqcKeyKind> {
    if method != Method::Pqc {
        return None;
    }
    match op {
        Op::Encrypt => Some(PqcKeyKind::KemPublic),
        Op::Decrypt => Some(PqcKeyKind::KemSecret),
        Op::Sign => Some(PqcKeyKind::DsaSecret),
        Op::Verify => Some(PqcKeyKind::DsaPublic),
    }
}

fn pqc_kind_tag(kind: Option<PqcKeyKind>) -> &'static str {
    match kind {
        Some(PqcKeyKind::KemPublic) | Some(PqcKeyKind::KemSecret) => "kem",
        Some(PqcKeyKind::DsaPublic) | Some(PqcKeyKind::DsaSecret) => "dsa",
        None => "-",
    }
}

fn pqc_kind_from_tag(tag: &str) -> Option<PqcKeyKind> {
    match tag {
        "kem" => Some(PqcKeyKind::KemPublic),
        "dsa" => Some(PqcKeyKind::DsaPublic),
        _ => None,
    }
}

fn secret_kind_from_tag(tag: &str) -> Option<PqcKeyKind> {
    match tag {
        "kem" => Some(PqcKeyKind::KemSecret),
        "dsa" => Some(PqcKeyKind::DsaSecret),
        _ => None,
    }
}

/// Rate die Schlüsselart eines geheimen PQC-Schlüssels anhand des Dateinamens.
/// Verschlüsselte PKCS#8-Dateien enthalten die Algorithmus-OID erst im
/// entschlüsselten Teil, deshalb ist der Name hier die einzige verfügbare
/// Information. Übliche Namen (`…-kem.sec.pem`, `…-dsa.sec.pem`) werden
/// erkannt; sonst bleibt die Art unbekannt und der Schlüssel wird bei beiden
/// PQC-Operationen angeboten.
fn secret_kind_from_name(path: &Path) -> Option<PqcKeyKind> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.contains("dsa") {
        Some(PqcKeyKind::DsaSecret)
    } else if name.contains("kem") {
        Some(PqcKeyKind::KemSecret)
    } else {
        None
    }
}

struct CryptoolApp {
    input: Option<PathBuf>,
    key: Option<PathBuf>,
    signature: Option<PathBuf>,
    recipients: Vec<RecipientKey>,
    secret_keys: Vec<SecretKey>,
    recipient_label: String,
    secret_label: String,
    method: Method,
    keygen: bool,
    text_mode: bool,
    text_input: String,
    text_output: String,
    user_id: String,
    password: String,
    password_confirm: String,
    op: Op,
    running: bool,
    progress: Option<Progress>,
    status: String,
    cancel: Option<Arc<AtomicBool>>,
    events: Option<Receiver<Event>>,
    ribbon_tab: RibbonTab,
    show_about: bool,
    show_keyserver: bool,
    keyserver_url: String,
    keyserver_entries: Vec<KeyserverEntry>,
    keyserver_selected: Option<usize>,
    keyserver_status: String,
    keyserver_loading: bool,
    keyserver_events: Option<Receiver<KeyserverEvent>>,
    keyserver_upload_path: Option<PathBuf>,
    keyserver_upload_token: String,
}

impl Default for CryptoolApp {
    fn default() -> Self {
        Self {
            input: None,
            key: None,
            signature: None,
            recipients: load_recipient_keys(),
            secret_keys: load_secret_keys(),
            recipient_label: String::new(),
            secret_label: String::new(),
            method: Method::Ctx,
            keygen: false,
            text_mode: false,
            text_input: String::new(),
            text_output: String::new(),
            user_id: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            op: Op::Encrypt,
            running: false,
            progress: None,
            status: "Datei oder Ordner auswählen".into(),
            cancel: None,
            events: None,
            ribbon_tab: RibbonTab::Start,
            show_about: false,
            show_keyserver: false,
            keyserver_url: load_keyserver_url(),
            keyserver_entries: Vec::new(),
            keyserver_selected: None,
            keyserver_status: String::new(),
            keyserver_loading: false,
            keyserver_events: None,
            keyserver_upload_path: None,
            keyserver_upload_token: String::new(),
        }
    }
}

impl CryptoolApp {
    fn import_recipient_key(&mut self) {
        let label = self.recipient_label.trim().to_owned();
        if label.is_empty() || label.contains(['\t', '\r', '\n']) {
            self.status = "Bitte einen Namen ohne Tab oder Zeilenumbruch eingeben.".into();
            return;
        }
        let Some(source) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        let Some(method) = detect_key_method(&source) else {
            self.status = "Die Datei ist kein bekannter cryptool- oder OpenPGP-Schlüssel.".into();
            return;
        };
        if method != self.method {
            self.status = format!(
                "Die Datei enthält einen {}-Schlüssel, nicht {}. Bitte im passenden Verfahren importieren.",
                method.label(),
                self.method.label()
            );
            return;
        }
        let Ok(bytes) = fs::read(&source) else {
            self.status = "Die Schlüsseldatei konnte nicht gelesen werden.".into();
            return;
        };
        let kind = if method == Method::Pqc {
            match pqc_detect_public_key_kind(&bytes) {
                Ok(kind) => Some(kind),
                Err(_) => {
                    self.status =
                        "Die Datei ist kein gültiger PQC-Schlüssel (SPKI als PEM oder DER).".into();
                    return;
                }
            }
        } else {
            None
        };
        match self.store_recipient_key(&label, &bytes, method, kind) {
            Ok(()) => {
                self.recipient_label.clear();
                self.status = format!("Öffentlicher Schlüssel für {label} importiert.");
            }
            Err(error) => self.status = error,
        }
    }

    fn upload_to_keyserver(&mut self) {
        if self.keyserver_loading {
            return;
        }

        let token = Zeroizing::new(self.keyserver_upload_token.trim().to_owned());
        if token.is_empty() || token.contains(['\r', '\n']) {
            self.keyserver_status = "Bitte den Upload-Token aus dem Keyserver eingeben.".into();
            return;
        }

        let Some(path) = self.keyserver_upload_path.clone() else {
            self.keyserver_status = "Bitte eine öffentliche Schlüsseldatei auswählen.".into();
            return;
        };

        let base = normalize_keyserver_url(&self.keyserver_url);
        let method = self.method;

        if base.is_empty() {
            self.keyserver_status = "Bitte die Keyserver-Adresse eingeben.".into();
            return;
        }

        self.keyserver_loading = true;
        self.keyserver_status = "Übertrage öffentlichen Schlüssel …".into();

        let (tx, rx) = mpsc::channel();
        self.keyserver_events = Some(rx);

        thread::spawn(move || {
            let result = Self::upload_keyserver_key(&base, token.as_str(), &path, method);
            let _ = tx.send(KeyserverEvent::Uploaded(result));
        });
    }

    fn upload_keyserver_key(
        base: &str,
        token: &str,
        path: &Path,
        method: Method,
    ) -> Result<String, String> {
        let metadata =
            fs::metadata(path).map_err(|e| format!("Datei konnte nicht gelesen werden: {e}"))?;

        if metadata.len() == 0 || metadata.len() > KEYSERVER_MAX_BYTES {
            return Err("Die Schlüsseldatei ist leer oder größer als 4 MB.".into());
        }

        let bytes = fs::read(path)
            .map_err(|e| format!("Schlüsseldatei konnte nicht gelesen werden: {e}"))?;

        match method {
            Method::Pgp if detect_key_method_bytes(&bytes) != Some(Method::Pgp) => {
                return Err("Die Datei enthält keinen gültigen OpenPGP-Schlüssel.".into());
            }
            Method::Pqc => match pqc_detect_public_key_kind(&bytes) {
                Ok(PqcKeyKind::KemPublic | PqcKeyKind::DsaPublic) => {}
                Ok(_) => return Err("Bitte einen öffentlichen PQC-Schlüssel auswählen.".into()),
                Err(_) => {
                    return Err(
                        "Die Datei enthält keinen gültigen öffentlichen PQC-Schlüssel.".into(),
                    )
                }
            },
            Method::Ctx => return Err("Der Keyserver unterstützt CTX-Schlüssel nicht.".into()),
            _ => {}
        }

        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(if method == Method::Pqc {
                "public-key.pem"
            } else {
                "public-key.asc"
            })
            .replace(['"', '\r', '\n'], "_");

        let boundary = format!(
            "----cryptool-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        let mut body = Vec::new();

        let (form_field, content_type) = match method {
            Method::Pgp => ("pgpfile", "application/pgp-keys"),
            Method::Pqc => ("pqcfile", "application/octet-stream"),
            Method::Ctx => unreachable!("CTX-Schlüssel werden oben abgelehnt"),
        };

        // Schlüsseldatei
        body.extend_from_slice(
            format!(
                "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"{form_field}\"; filename=\"{filename}\"\r\n\
             Content-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );

        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let url = format!("{base}/api/keys/{}", method.tag());

        let response = ureq::post(&url)
            .timeout(KEYSERVER_TIMEOUT)
            .set(
                "Content-Type",
                &format!("multipart/form-data; boundary={boundary}"),
            )
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {token}"))
            .send_bytes(&body)
            .map_err(|error| match error {
                ureq::Error::Status(code, response) => {
                    let mut message = String::new();

                    let _ = response
                        .into_reader()
                        .take(64 * 1024)
                        .read_to_string(&mut message);

                    if message.trim().is_empty() {
                        format!("Keyserver meldet HTTP {code}.")
                    } else {
                        format!("Keyserver meldet HTTP {code}: {}", message.trim())
                    }
                }
                ureq::Error::Transport(error) => {
                    format!("Keyserver nicht erreichbar: {error}")
                }
            })?;

        let mut response_body = String::new();

        response
            .into_reader()
            .take(64 * 1024)
            .read_to_string(&mut response_body)
            .map_err(|e| format!("Serverantwort konnte nicht gelesen werden: {e}"))?;

        Ok(format!(
            "{}-Schlüssel erfolgreich hochgeladen.",
            method.label()
        ))
    }

    /// Legt einen öffentlichen Schlüssel im Benutzerordner ab und trägt ihn in
    /// die Schlüsselverwaltung ein.
    fn store_recipient_key(
        &mut self,
        label: &str,
        bytes: &[u8],
        method: Method,
        kind: Option<PqcKeyKind>,
    ) -> Result<(), String> {
        let label = label.replace(['\t', '\r', '\n'], " ").trim().to_owned();
        if label.is_empty() {
            return Err("Bitte einen Namen für den Schlüssel angeben.".into());
        }
        if let Some(existing) = self.recipients.iter().find(|entry| {
            entry.method == method
                && fs::read(&entry.path)
                    .map(|existing| existing == bytes)
                    .unwrap_or(false)
        }) {
            self.key = Some(existing.path.clone());
            return Ok(());
        }
        let Some(directory) = recipient_key_dir() else {
            return Err("Der Speicherort für Schlüssel ist nicht verfügbar.".into());
        };
        fs::create_dir_all(&directory)
            .map_err(|error| format!("Schlüsselordner konnte nicht angelegt werden: {error}"))?;
        let next_id = (1u64..)
            .find(|id| !directory.join(format!("recipient-{id}.key")).exists())
            .unwrap_or(1);
        let file_name = format!("recipient-{next_id}.key");
        let destination = directory.join(&file_name);
        fs::write(&destination, bytes)
            .map_err(|error| format!("Schlüssel konnte nicht importiert werden: {error}"))?;
        let manifest = directory.join("recipients.tsv");
        let mut contents = fs::read_to_string(&manifest).unwrap_or_default();
        contents.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            method.tag(),
            pqc_kind_tag(kind),
            label,
            file_name
        ));
        if let Err(error) = fs::write(&manifest, contents) {
            let _ = fs::remove_file(&destination);
            return Err(format!(
                "Schlüsselverwaltung konnte nicht gespeichert werden: {error}"
            ));
        }
        self.recipients.push(RecipientKey {
            label: label.clone(),
            path: destination.clone(),
            method,
            kind,
        });
        self.key = Some(destination);
        Ok(())
    }

    fn open_keyserver(&mut self) {
        self.show_keyserver = true;
        self.keyserver_selected = None;
        if self.keyserver_entries.is_empty() && self.keyserver_events.is_none() {
            self.load_keyserver_list();
        }
    }

    fn close_keyserver_page(&mut self) {
        if !self.show_keyserver {
            return;
        }
        let url = normalize_keyserver_url(&self.keyserver_url);
        if !url.is_empty() {
            self.keyserver_url = url.clone();
            save_keyserver_url(&url);
        }
        self.keyserver_upload_token.zeroize();
        self.show_keyserver = false;
    }

    fn load_keyserver_list(&mut self) {
        if self.keyserver_loading {
            return;
        }
        let base = normalize_keyserver_url(&self.keyserver_url);
        if base.is_empty() {
            self.keyserver_status = "Bitte die Adresse des Keyservers eingeben.".into();
            return;
        }
        self.keyserver_url = base.clone();
        save_keyserver_url(&base);
        self.keyserver_loading = true;
        self.keyserver_status = "Lade Schlüssel vom Keyserver …".into();
        self.keyserver_entries.clear();
        self.keyserver_selected = None;
        let (tx, rx) = mpsc::channel();
        self.keyserver_events = Some(rx);
        thread::spawn(move || {
            let result = fetch_keyserver_list(&base);
            let _ = tx.send(KeyserverEvent::Listed(result));
        });
    }

    fn import_from_keyserver(&mut self) {
        if self.keyserver_loading {
            return;
        }
        let Some(index) = self.keyserver_selected else {
            self.keyserver_status = "Bitte zuerst einen Schlüssel auswählen.".into();
            return;
        };
        let Some(entry) = self.keyserver_entries.get(index).cloned() else {
            self.keyserver_status = "Bitte zuerst einen Schlüssel auswählen.".into();
            return;
        };
        let base = normalize_keyserver_url(&self.keyserver_url);
        if base.is_empty() {
            self.keyserver_status = "Bitte die Adresse des Keyservers eingeben.".into();
            return;
        }
        let mut label = entry.owner.trim().to_owned();

        if label.is_empty() {
            label = format!("Schlüssel {}", entry.id);
        }
        self.keyserver_loading = true;
        self.keyserver_status = format!("Lade Schlüssel für {label} …");
        let (tx, rx) = mpsc::channel();
        self.keyserver_events = Some(rx);
        thread::spawn(move || {
            let result = fetch_keyserver_key(&base, entry.id);
            let _ = tx.send(KeyserverEvent::Downloaded { label, result });
        });
    }

    fn poll_keyserver_events(&mut self) {
        let Some(events) = self.keyserver_events.take() else {
            return;
        };
        let mut received = false;
        while let Ok(event) = events.try_recv() {
            received = true;
            match event {
                KeyserverEvent::Listed(result) => {
                    self.keyserver_loading = false;
                    match result {
                        Ok(entries) => {
                            if entries.is_empty() {
                                self.keyserver_status =
                                    "Keine Schlüssel auf dem Keyserver gefunden.".into();
                            } else {
                                self.keyserver_status = format!(
                                    "{} Schlüssel gefunden. Eintrag auswählen und importieren.",
                                    entries.len()
                                );
                            }
                            self.keyserver_entries = entries;
                            self.keyserver_selected = None;
                        }
                        Err(error) => {
                            self.keyserver_entries.clear();
                            self.keyserver_selected = None;
                            self.keyserver_status = format!("Fehler: {error}");
                        }
                    }
                }
                KeyserverEvent::Downloaded { label, result } => {
                    self.keyserver_loading = false;
                    match result {
                        Ok(bytes) => {
                            let key = match detect_key_method_bytes(&bytes) {
                                Some(Method::Pgp) => Some((Method::Pgp, None)),
                                Some(Method::Pqc) => match pqc_detect_public_key_kind(&bytes) {
                                    Ok(kind @ (PqcKeyKind::KemPublic | PqcKeyKind::DsaPublic)) => {
                                        Some((Method::Pqc, Some(kind)))
                                    }
                                    _ => None,
                                },
                                _ => None,
                            };
                            match key {
                                Some((method, kind)) => {
                                    match self.store_recipient_key(&label, &bytes, method, kind) {
                                        Ok(()) => {
                                            self.keyserver_status = format!("{}-Schlüssel für {label} importiert.", method.label());
                                            self.status = self.keyserver_status.clone();
                                        }
                                        Err(error) => self.keyserver_status = format!("Fehler: {error}"),
                                    }
                                }
                                None => self.keyserver_status = "Der Keyserver hat keinen gültigen öffentlichen OpenPGP- oder PQC-Schlüssel geliefert.".into(),
                            }
                        }
                        Err(error) => self.keyserver_status = format!("Fehler: {error}"),
                    }
                }
                KeyserverEvent::Uploaded(result) => {
                    self.keyserver_loading = false;

                    match result {
                        Ok(message) => {
                            self.keyserver_upload_path = None;
                            self.keyserver_status = message;

                            self.load_keyserver_list();
                        }
                        Err(error) => {
                            self.keyserver_status = format!("Upload fehlgeschlagen: {error}");
                        }
                    }
                }
            }
        }
        if !received {
            self.keyserver_events = Some(events);
        }
    }

    fn import_secret_key(&mut self) {
        let Some(source) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        let Some(method) = detect_key_method(&source) else {
            self.status = "Die Datei ist kein bekannter Schlüssel.".into();
            return;
        };
        if method != self.method {
            self.status = format!(
                "Die Datei enthält einen {}-Schlüssel, nicht {}. Bitte im passenden Verfahren öffnen.",
                method.label(),
                self.method.label()
            );
            return;
        }
        let Ok(source_bytes) = fs::read(&source) else {
            self.status = "Der geheime Schlüssel konnte nicht gelesen werden.".into();
            return;
        };
        let kind = if method == Method::Pqc {
            secret_kind_from_name(&source)
        } else {
            None
        };
        if let Some(existing) = self.secret_keys.iter().find(|entry| {
            entry.method == method
                && fs::read(&entry.path)
                    .map(|bytes| bytes == source_bytes)
                    .unwrap_or(false)
        }) {
            self.key = Some(existing.path.clone());
            self.status = format!("Geheimer Schlüssel „{}“ ausgewählt.", existing.label);
            return;
        }
        let Some(directory) = secret_key_dir() else {
            self.status = "Der Speicherort für Schlüssel ist nicht verfügbar.".into();
            return;
        };
        if let Err(error) = fs::create_dir_all(&directory) {
            self.status = format!("Schlüsselordner konnte nicht angelegt werden: {error}");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
                self.status = format!("Schlüsselordner konnte nicht geschützt werden: {error}");
                return;
            }
        }
        let next_id = (1u64..)
            .find(|id| !directory.join(format!("secret-{id}.key")).exists())
            .unwrap_or(1);
        let file_name = format!("secret-{next_id}.key");
        let destination = directory.join(&file_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = options
            .open(&destination)
            .and_then(|mut file| file.write_all(&source_bytes));
        if let Err(error) = write_result {
            self.status = format!("Geheimer Schlüssel konnte nicht gespeichert werden: {error}");
            return;
        }
        let entered_label = self.secret_label.trim().replace(['\t', '\r', '\n'], " ");
        let label = if entered_label.is_empty() {
            source
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| !stem.is_empty())
                .unwrap_or("Geheimer Schlüssel")
                .to_owned()
        } else {
            entered_label
        };
        let manifest = directory.join("secret-keys.tsv");
        let mut contents = fs::read_to_string(&manifest).unwrap_or_default();
        contents.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            method.tag(),
            pqc_kind_tag(kind),
            label,
            file_name
        ));
        if let Err(error) = fs::write(&manifest, contents) {
            let _ = fs::remove_file(&destination);
            self.status = format!("Schlüsselverwaltung konnte nicht gespeichert werden: {error}");
            return;
        }
        self.secret_keys.push(SecretKey {
            label: label.clone(),
            path: destination.clone(),
            method,
            kind,
        });
        self.key = Some(destination);
        self.secret_label.clear();
        self.status = format!("Geheimer Schlüssel „{label}“ gemerkt.");
    }

    fn set_mode(&mut self, op: Op) {
        if self.running || self.op == op {
            return;
        }
        // Öffentliche und geheime Schlüssel sind nicht austauschbar. Beim
        // Wechsel der Schlüsselrolle darf keine falsche Auswahl stehen bleiben.
        if self.op.uses_secret_key() != op.uses_secret_key()
            || required_pqc_key_kind(self.method, self.op) != required_pqc_key_kind(self.method, op)
        {
            self.key = None;
        }
        self.op = op;
        if !op.is_text_allowed() {
            self.text_mode = false;
        }
        self.text_input.clear();
        self.text_output.clear();
        self.input = None;
        self.signature = None;
        self.password.zeroize();
        self.password_confirm.zeroize();
        self.progress = None;
        self.status = match op {
            Op::Encrypt if self.method.key_based() && self.text_mode => "Text eingeben".into(),
            Op::Encrypt => "Datei oder Ordner auswählen".into(),
            Op::Decrypt if self.method.key_based() && self.text_mode => {
                format!("{}: Text zum Entschlüsseln einfügen", self.method.label())
            }
            Op::Decrypt => format!("{}: Datei zum Entschlüsseln auswählen", self.method.label()),
            Op::Sign => format!("{}: Datei zum Signieren auswählen", self.method.label()),
            Op::Verify => format!(
                "{}: Datei und Signatur zum Prüfen auswählen",
                self.method.label()
            ),
        };
    }

    fn set_method(&mut self, method: Method) {
        if self.running || self.method == method {
            return;
        }
        self.method = method;
        self.keygen = false;
        self.text_mode = false;
        self.input = None;
        self.key = None;
        self.signature = None;
        if method == Method::Ctx && !self.op.is_text_allowed() {
            self.op = Op::Encrypt;
        }
        self.password.zeroize();
        self.password_confirm.zeroize();
        self.progress = None;
        self.status = "Datei oder Ordner auswählen".into();
    }

    fn generate_keys(&mut self) {
        if self.method == Method::Pgp && self.user_id.trim().is_empty() {
            self.status = "Bitte eine Nutzerkennung eingeben.".into();
            return;
        }
        if self.password.is_empty() {
            self.status = "Bitte eine Passphrase eingeben.".into();
            return;
        }
        if self.password != self.password_confirm {
            self.status = "Die Passphrasen stimmen nicht überein.".into();
            return;
        }

        let method = self.method;
        let mut password = std::mem::take(&mut self.password);
        self.password_confirm.zeroize();
        let passphrase = SecretString::new(std::mem::take(&mut password));
        password.zeroize();

        let (tx, rx) = mpsc::channel();
        self.events = Some(rx);
        self.running = true;

        match method {
            Method::Pgp => {
                let (secret_name, public_name) = ("schluessel.sec.asc", "schluessel.pub.asc");
                let Some(secret_out) = rfd::FileDialog::new()
                    .set_file_name(secret_name)
                    .save_file()
                else {
                    self.running = false;
                    return;
                };
                let Some(public_out) = rfd::FileDialog::new()
                    .set_file_name(public_name)
                    .save_file()
                else {
                    self.running = false;
                    return;
                };
                if secret_out == public_out {
                    self.status =
                        "Geheimer und öffentlicher Schlüssel benötigen getrennte Dateien.".into();
                    self.running = false;
                    return;
                }
                let user_id = self.user_id.trim().to_owned();
                self.status = "Schlüsselpaar wird erzeugt …".into();
                thread::spawn(move || {
                    let result =
                        pgp_generate_key(&user_id, passphrase, &secret_out, &public_out, false)
                            .map(|()| {
                                format!(
                                    "Schlüsselpaar erstellt: {} und {}",
                                    public_out.display(),
                                    secret_out.display()
                                )
                            })
                            .map_err(|error| error.to_string());
                    let _ = tx.send(Event::Finished(result));
                });
            }
            Method::Pqc => {
                let Some(directory) = rfd::FileDialog::new().pick_folder() else {
                    self.running = false;
                    return;
                };
                // Cryptool verwendet für PQC-Schlüssel wie bei OpenPGP
                // ausschließlich PEM-Dateien. DER bleibt als Importformat
                // in der Bibliothek unterstützt.
                let format = PqcKeyFormat::Pem;
                let kem_secret = directory.join("schluessel-kem.sec.pem");
                let kem_public = directory.join("schluessel-kem.pub.pem");
                let dsa_secret = directory.join("schluessel-dsa.sec.pem");
                let dsa_public = directory.join("schluessel-dsa.pub.pem");
                self.status = "ML-KEM- und ML-DSA-Schlüssel werden erzeugt …".into();
                thread::spawn(move || {
                    let result = pqc_generate_key(
                        passphrase,
                        &kem_secret,
                        &kem_public,
                        &dsa_secret,
                        &dsa_public,
                        format,
                        false,
                    )
                    .map(|()| {
                        format!(
                            "Schlüssel erstellt in {}: ML-KEM und ML-DSA (geheim + öffentlich)",
                            directory.display()
                        )
                    })
                    .map_err(|error| error.to_string());
                    let _ = tx.send(Event::Finished(result));
                });
            }
            Method::Ctx => {
                self.running = false;
                return;
            }
        }
    }

    fn start(&mut self) {
        if self.method.key_based() && self.text_mode {
            self.start_text();
            return;
        }
        let Some(input) = self.input.clone() else {
            self.status = "Bitte zuerst eine Eingabe auswählen.".into();
            return;
        };
        if matches!(self.op, Op::Sign | Op::Verify) && input.is_dir() {
            self.status = "Signieren und Prüfen wird nur für einzelne Dateien unterstützt.".into();
            return;
        }
        let key = if self.method.key_based() {
            match self.key.clone() {
                Some(key) => Some(key),
                None => {
                    self.status = "Bitte den passenden Schlüssel auswählen.".into();
                    return;
                }
            }
        } else {
            None
        };
        let needs_password = !self.method.key_based() || self.op.uses_secret_key() || self.keygen;
        if needs_password && self.password.is_empty() {
            self.status = "Bitte ein Passwort bzw. eine Passphrase eingeben.".into();
            return;
        }
        if self.method == Method::Ctx
            && self.op == Op::Encrypt
            && self.password != self.password_confirm
        {
            self.status = "Die Passwörter stimmen nicht überein.".into();
            return;
        }

        let mut password = std::mem::take(&mut self.password);
        self.password_confirm.zeroize();
        let secret = SecretString::new(std::mem::take(&mut password));
        password.zeroize();
        let op = self.op;
        let method = self.method;
        let output = default_output(&input, op, method);
        let signature = if op == Op::Verify {
            Some(
                self.signature
                    .clone()
                    .unwrap_or_else(|| default_signature(&input, method)),
            )
        } else {
            None
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel();
        self.cancel = Some(cancel);
        self.events = Some(rx);
        self.progress = None;
        self.running = true;
        self.status = "Verarbeitung läuft …".into();

        thread::spawn(move || {
            run_operation(
                input,
                output,
                signature,
                key,
                secret,
                op,
                method,
                worker_cancel,
                tx,
            )
        });
    }

    fn start_text(&mut self) {
        let Some(key) = self.key.clone() else {
            self.status = "Bitte den passenden Schlüssel auswählen.".into();
            return;
        };
        if self.text_input.is_empty() {
            self.status = "Bitte Text eingeben.".into();
            return;
        }
        if self.op == Op::Decrypt && self.password.is_empty() {
            self.status = "Bitte die Passphrase des geheimen Schlüssels eingeben.".into();
            return;
        }
        // Eingabe stehen lassen, damit Klartext bzw. verschlüsselter Text beim
        // erneuten Ausführen nicht verloren geht.
        let input = self.text_input.clone();
        let passphrase = SecretString::new(std::mem::take(&mut self.password));
        self.password_confirm.zeroize();
        self.running = true;
        self.status = "Text wird verarbeitet …".into();
        self.text_output.clear();
        let (tx, rx) = mpsc::channel();
        self.events = Some(rx);
        let decrypting = self.op == Op::Decrypt;
        let method = self.method;
        thread::spawn(move || {
            let result = match method {
                Method::Pgp => {
                    if !decrypting {
                        pgp_encrypt_text(&input, &key)
                    } else {
                        pgp_decrypt_text(&input, &key, passphrase)
                    }
                }
                Method::Pqc => {
                    if !decrypting {
                        pqc_encrypt_text(&input, &key)
                    } else {
                        pqc_decrypt_text(&input, &key, passphrase)
                    }
                }
                Method::Ctx => unreachable!("CTX hat keinen Textmodus"),
            }
            .map_err(|error| error.to_string());
            let _ = tx.send(Event::Finished(result));
        });
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        self.poll_keyserver_events();

        if let Some(events) = &self.events {
            while let Ok(event) = events.try_recv() {
                match event {
                    Event::Progress(progress) => self.progress = Some(progress),
                    Event::Finished(result) => {
                        self.running = false;
                        self.cancel = None;
                        if self.method.key_based() && self.text_mode {
                            match result {
                                Ok(output) => {
                                    self.text_output = output;
                                    self.status = "Text verarbeitet.".into();
                                }
                                Err(error) => self.status = format!("Fehler: {error}"),
                            }
                        } else {
                            self.status = result.unwrap_or_else(|error| format!("Fehler: {error}"));
                        }
                    }
                }
                ctx.request_repaint();
            }
        }

        if self.running || self.keyserver_loading {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

impl CryptoolApp {
    fn summary(&self) -> String {
        let name = self.method.label();
        if self.method.key_based() && self.keygen {
            format!("{name} · Schlüsselpaar erstellen")
        } else if self.method.key_based() && self.text_mode {
            format!("{name} · Text {}", self.op.verb())
        } else if self.method == Method::Ctx {
            format!("CTX · {}", self.op.title())
        } else if self.op == Op::Verify {
            format!("{name} · Signatur prüfen")
        } else {
            format!("{name} · Datei {}", self.op.verb())
        }
    }

    fn subtitle(&self) -> String {
        if self.method.key_based() && self.keygen {
            format!("{}-Schlüsselpaar erzeugen.", self.method.label())
        } else if self.method.key_based() && self.text_mode {
            "Text verschlüsseln oder entschlüsseln.".to_owned()
        } else {
            match self.op {
                Op::Encrypt => "Datei oder Ordner auswählen und verschlüsseln.".to_owned(),
                Op::Decrypt => "Datei oder Ordner auswählen und entschlüsseln.".to_owned(),
                Op::Sign => "Einzelne Datei auswählen und abgetrennt signieren.".to_owned(),
                Op::Verify => "Datei und Signatur auswählen und prüfen.".to_owned(),
            }
        }
    }

    fn start_ribbon(&mut self, ui: &mut egui::Ui) {
        ribbon_group(ui, "Eingabe", |ui| {
            let text_active = self.method.key_based()
                && self.text_mode
                && !self.keygen
                && self.op.is_text_allowed();
            if ribbon_button(
                ui,
                RibbonIcon::File,
                "Datei öffnen",
                false,
                !self.running && !text_active,
            )
            .clicked()
            {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.input = Some(path);
                    self.signature = None;
                }
            }
            let folder_available = !self.running && !text_active && self.op == Op::Encrypt;
            if ribbon_button(
                ui,
                RibbonIcon::Folder,
                "Ordner öffnen",
                false,
                folder_available,
            )
            .clicked()
            {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.input = Some(path);
                    self.signature = None;
                }
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Vorgang", |ui| {
            let available = !self.running && !self.keygen;
            if ribbon_button(
                ui,
                RibbonIcon::Lock,
                "Verschlüsseln",
                self.op == Op::Encrypt,
                available,
            )
            .clicked()
            {
                self.set_mode(Op::Encrypt);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Unlock,
                "Entschlüsseln",
                self.op == Op::Decrypt,
                available,
            )
            .clicked()
            {
                self.set_mode(Op::Decrypt);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Signature,
                "Signieren",
                self.op == Op::Sign,
                available && self.method.key_based(),
            )
            .clicked()
            {
                self.set_mode(Op::Sign);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Check,
                "Prüfen",
                self.op == Op::Verify,
                available && self.method.key_based(),
            )
            .clicked()
            {
                self.set_mode(Op::Verify);
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Verfahren", |ui| {
            if ribbon_button(
                ui,
                RibbonIcon::Box,
                "CTX",
                self.method == Method::Ctx,
                !self.running,
            )
            .clicked()
            {
                self.set_method(Method::Ctx);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Key,
                "OpenPGP",
                self.method == Method::Pgp,
                !self.running,
            )
            .clicked()
            {
                self.set_method(Method::Pgp);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Shield,
                "PQC",
                self.method == Method::Pqc,
                !self.running,
            )
            .clicked()
            {
                self.set_method(Method::Pqc);
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Ansicht", |ui| {
            let text_available = self.method.key_based()
                && !self.keygen
                && !self.running
                && self.op.is_text_allowed();
            if ribbon_button(ui, RibbonIcon::Text, "Text", self.text_mode, text_available).clicked()
            {
                self.text_mode = true;
                self.status = match self.op {
                    Op::Decrypt => {
                        format!("{}: Text zum Entschlüsseln einfügen", self.method.label())
                    }
                    _ => "Text eingeben".into(),
                };
            }
            if ribbon_button(
                ui,
                RibbonIcon::Files,
                "Dateien",
                !self.text_mode,
                !self.running,
            )
            .clicked()
            {
                self.text_mode = false;
                self.status = match self.op {
                    Op::Decrypt => {
                        format!("{}: Datei zum Entschlüsseln auswählen", self.method.label())
                    }
                    _ => "Datei oder Ordner auswählen".into(),
                };
            }
        });
    }

    fn keys_ribbon(&mut self, ui: &mut egui::Ui) {
        ribbon_group(ui, "Schlüsselpaar", |ui| {
            let available = self.method.key_based() && !self.running;
            let create =
                ribbon_button(ui, RibbonIcon::KeyPlus, "Erstellen", self.keygen, available);
            if create.clicked() {
                self.close_keyserver_page();
                self.keygen = true;
                self.password.zeroize();
                self.password_confirm.zeroize();
                self.status = "Nutzerkennung und Passphrase eingeben.".into();
            }
            let process =
                ribbon_button(ui, RibbonIcon::Mail, "Verarbeiten", !self.keygen, available);
            if process.clicked() {
                self.close_keyserver_page();
                self.keygen = false;
                self.password.zeroize();
                self.password_confirm.zeroize();
                self.status = "Datei oder Ordner auswählen".into();
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Öffentlicher Schlüssel", |ui| {
            let available = self.method.key_based() && !self.running && !self.keygen;
            if ribbon_button(ui, RibbonIcon::Server, "Keyserver", false, available).clicked() {
                self.open_keyserver();
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Geheimer Schlüssel", |ui| {
            let available = self.method.key_based() && self.op.uses_secret_key() && !self.running;
            if ribbon_button(ui, RibbonIcon::KeyOpen, "Öffnen", false, available).clicked() {
                self.close_keyserver_page();
                self.import_secret_key();
            }
        });
    }

    fn help_ribbon(&mut self, ui: &mut egui::Ui) {
        ribbon_group(ui, "Informationen", |ui| {
            if ribbon_button(ui, RibbonIcon::Help, "Über", false, true).clicked() {
                self.show_about = true;
            }
        });
    }

    fn keyserver_page(&mut self, ui: &mut egui::Ui) {
        let mut close = false;
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.set_max_width(620.0);
            ui.heading("OpenPGP- und PQC-Keyserver");
            ui.label(
                "Schlüssel vom Keyserver abrufen oder einen öffentlichen Schlüssel hochladen.",
            );
            ui.add_space(16.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(249, 250, 251))
                .stroke(egui::Stroke::new(
                    1.0,
                    egui::Color32::from_rgb(202, 209, 217),
                ))
                .corner_radius(egui::CornerRadius::same(12))
                .inner_margin(egui::Margin::same(18))
                .show(ui, |ui| {
                    ui.set_max_width(560.0);

                    // Adresse + Abrufen
                    ui.label("Adresse des Keyservers");
                    ui.horizontal(|ui| {
                        let address_width = (ui.available_width() - 96.0).max(160.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.keyserver_url)
                                .hint_text("http://localhost:8080")
                                .desired_width(address_width),
                        );
                        if ui
                            .add_enabled(!self.keyserver_loading, egui::Button::new("Abrufen"))
                            .clicked()
                        {
                            self.load_keyserver_list();
                        }
                    });

                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(&self.keyserver_status)
                            .size(11.0)
                            .color(egui::Color32::from_rgb(76, 88, 102)),
                    );
                    ui.separator();

                    // Liste
                    if self.keyserver_entries.is_empty() {
                        ui.label("Noch keine Schlüssel geladen.");
                    } else {
                        let visible_count = self
                            .keyserver_entries
                            .iter()
                            .filter(|entry| keyserver_entry_matches_method(entry, self.method))
                            .count();
                        if visible_count == 0 {
                            ui.label(format!(
                                "Keine {}-Schlüssel in der Liste.",
                                self.method.label()
                            ));
                        }
                        egui::ScrollArea::vertical()
                            .max_height(220.0)
                            .show(ui, |ui| {
                                for (index, entry) in self.keyserver_entries.iter().enumerate() {
                                    if !keyserver_entry_matches_method(entry, self.method) {
                                        continue;
                                    }
                                    let text = if entry.filename.is_empty() {
                                        format!("{} · ID {}", entry.owner, entry.id)
                                    } else {
                                        format!(
                                            "{} · {} · ID {}",
                                            entry.owner, entry.filename, entry.id
                                        )
                                    };
                                    let selected = self.keyserver_selected == Some(index);
                                    if ui.selectable_label(selected, text).clicked() {
                                        self.keyserver_selected = Some(index);
                                    }
                                }
                            });
                    }

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let can_import =
                            self.keyserver_selected.is_some() && !self.keyserver_loading;
                        if ui
                            .add_enabled(can_import, egui::Button::new("In cryptool importieren"))
                            .clicked()
                        {
                            self.import_from_keyserver();
                        }
                        if self.keyserver_loading {
                            ui.spinner();
                        }
                    });

                    // Upload
                    ui.add_space(8.0);
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "Öffentlichen {}-Schlüssel hochladen",
                            self.method.label()
                        ))
                        .strong(),
                    );
                    ui.label("Token aus der Keyserver-Verwaltung hier einfügen:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keyserver_upload_token)
                            .password(true)
                            .hint_text("Upload-Token hier einfügen")
                            .desired_width(f32::INFINITY),
                    );
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !self.keyserver_loading,
                                egui::Button::new("Schlüsseldatei auswählen"),
                            )
                            .clicked()
                        {
                            let dialog = rfd::FileDialog::new();
                            let selected = if self.method == Method::Pqc {
                                dialog
                                    .add_filter("Öffentliche PQC-Schlüssel", &["pem", "pqc"])
                                    .pick_file()
                            } else {
                                dialog
                                    .add_filter("OpenPGP-Schlüssel", &["asc", "pgp", "gpg"])
                                    .pick_file()
                            };
                            if let Some(path) = selected {
                                self.keyserver_upload_path = Some(path);
                            }
                        }
                        if let Some(path) = &self.keyserver_upload_path {
                            ui.small(path.file_name().unwrap_or_default().to_string_lossy());
                        }
                    });
                    let can_upload = !self.keyserver_loading
                        && !self.keyserver_upload_token.trim().is_empty()
                        && self.keyserver_upload_path.is_some();
                    if ui
                        .add_enabled(
                            can_upload,
                            egui::Button::new(format!(
                                "Öffentlichen {}-Schlüssel hochladen",
                                self.method.label()
                            )),
                        )
                        .clicked()
                    {
                        self.upload_to_keyserver();
                    }

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Schließen").clicked() {
                            close = true;
                        }
                    });
                });
        });

        if close {
            self.close_keyserver_page();
        }
    }
}

impl eframe::App for CryptoolApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events(&ui.ctx().clone());
        let background = egui::Color32::from_rgb(232, 235, 239);
        ui.painter()
            .rect_filled(ui.max_rect(), egui::CornerRadius::ZERO, background);
        apply_visuals(ui);

        egui::Panel::top("cryptool_ribbon")
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(250, 251, 252)))
            .show(ui, |ui| {
                egui::Frame::new()
                    .fill(ACCENT)
                    .inner_margin(egui::Margin::symmetric(14, 6))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("CRYPT•OOL")
                                    .size(12.0)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new("LOKALE VERSCHLÜSSELUNG")
                                            .size(9.5)
                                            .color(egui::Color32::from_rgb(212, 240, 233)),
                                    );
                                },
                            );
                        });
                    });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.spacing_mut().item_spacing.x = 2.0;
                    for (tab, label) in [
                        (RibbonTab::Start, "Start"),
                        (RibbonTab::Keys, "Schlüssel"),
                        (RibbonTab::Help, "Hilfe"),
                    ] {
                        if ribbon_tab(ui, self.ribbon_tab == tab, label).clicked() {
                            self.close_keyserver_page();
                            self.ribbon_tab = tab;
                        }
                    }
                });
                ui.add_space(4.0);
                let (divider, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 1.0),
                    egui::Sense::hover(),
                );
                ui.painter().rect_filled(
                    divider,
                    egui::CornerRadius::ZERO,
                    egui::Color32::from_rgb(223, 228, 233),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    match self.ribbon_tab {
                        RibbonTab::Start => self.start_ribbon(ui),
                        RibbonTab::Keys => self.keys_ribbon(ui),
                        RibbonTab::Help => self.help_ribbon(ui),
                    }
                });
                ui.add_space(6.0);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(background)
                    .inner_margin(egui::Margin::same(0)),
            )
            .show(ui, |ui| {
                if self.show_keyserver {
                    egui::ScrollArea::vertical().show(ui, |ui| self.keyserver_page(ui));
                } else {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.set_max_width(620.0);
                        ui.vertical_centered(|ui| {
                            ui.heading(
                                egui::RichText::new("Dateien sicher schützen")
                                    .size(26.0)
                                    .strong(),
                            );
                            ui.label(
                                egui::RichText::new(self.subtitle())
                                    .color(egui::Color32::from_rgb(94, 107, 121)),
                            );
                        });
                        ui.add_space(18.0);

                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(249, 250, 251))
                            .stroke(egui::Stroke::new(
                                1.0,
                                egui::Color32::from_rgb(202, 209, 217),
                            ))
                            .corner_radius(egui::CornerRadius::same(16))
                            .inner_margin(egui::Margin::same(22))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.with_layout(
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.set_width(ui.available_width());

                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(self.summary())
                                                    .size(11.5)
                                                    .strong()
                                                    .color(ACCENT),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new("MENÜBAND")
                                                            .size(9.5)
                                                            .color(egui::Color32::from_rgb(
                                                                148, 158, 168,
                                                            )),
                                                    );
                                                },
                                            );
                                        });
                                        ui.add_space(6.0);
                                        ui.separator();
                                        ui.add_space(10.0);

                                        if self.method == Method::Pgp && self.keygen {
                                            ui.label("Nutzerkennung (Name und optional E-Mail)");
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.user_id)
                                                    .hint_text("Anna Beispiel <anna@example.org>")
                                                    .desired_width(f32::INFINITY),
                                            );
                                        }

                                        if self.method == Method::Pqc && self.keygen {
                                            ui.label(
                                                egui::RichText::new(
                                                    "Es werden vier Schlüsseldateien erzeugt: \
                                                     ML-KEM und ML-DSA, jeweils geheim und öffentlich.",
                                                )
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(105, 117, 130)),
                                            );
                                        }

                                        if self.method.key_based() && !self.keygen {
                                            ui.add_space(12.0);
                                            if !self.op.uses_secret_key() {
                                                ui.label(format!(
                                                    "{} ({})",
                                                    if self.op == Op::Verify {
                                                        "Öffentlicher Schlüssel des Unterzeichners"
                                                    } else {
                                                        "Empfängerschlüssel"
                                                    },
                                                    self.method.label()
                                                ));
                                                if !self.recipients.is_empty() {
                                                    let required = required_pqc_key_kind(
                                                        self.method, self.op,
                                                    );
                                                    let candidates: Vec<&RecipientKey> = self
                                                        .recipients
                                                        .iter()
                                                        .filter(|entry| entry.method == self.method)
                                                        .filter(|entry| {
                                                            entry.kind.is_none()
                                                                || entry.kind == required
                                                        })
                                                        .collect();
                                                    if candidates.is_empty() {
                                                        ui.label(
                                                            egui::RichText::new(format!(
                                                                "Noch kein {}-Schlüssel importiert.",
                                                                self.method.label()
                                                            ))
                                                            .size(11.0)
                                                            .color(egui::Color32::from_rgb(
                                                                105, 117, 130,
                                                            )),
                                                        );
                                                    } else {
                                                        let selected = self
                                                            .key
                                                            .as_ref()
                                                            .and_then(|path| {
                                                                candidates
                                                                    .iter()
                                                                    .find(|entry| {
                                                                        &entry.path == path
                                                                    })
                                                                    .copied()
                                                            })
                                                            .map_or(
                                                                "Schlüssel auswählen",
                                                                |entry| entry.label.as_str(),
                                                            );
                                                        egui::ComboBox::from_id_salt(
                                                            "recipient_keys",
                                                        )
                                                        .selected_text(selected)
                                                        .show_ui(ui, |ui| {
                                                            for entry in &candidates {
                                                                if ui
                                                                    .selectable_label(
                                                                        self.key.as_ref()
                                                                            == Some(&entry.path),
                                                                        &entry.label,
                                                                    )
                                                                    .clicked()
                                                                {
                                                                    self.key = Some(
                                                                        entry.path.clone(),
                                                                    );
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                                ui.horizontal(|ui| {
                                                    ui.add(
                                                        egui::TextEdit::singleline(
                                                            &mut self.recipient_label,
                                                        )
                                                        .hint_text("Name, z. B. Anna oder Team"),
                                                    );
                                                    if ui.button("Importieren").clicked() {
                                                        self.import_recipient_key();
                                                    }
                                                });
                                                if let Some(path) = &self.key {
                                                    ui.small(path.display().to_string());
                                                }
                                            } else {
                                                ui.label(match self.op {
                                                    Op::Sign => {
                                                        "Signaturschlüssel (geheimer Schlüssel)"
                                                    }
                                                    Op::Decrypt => {
                                                        "Entschlüsselungsschlüssel (geheimer Schlüssel)"
                                                    }
                                                    _ => "Geheimer Schlüssel",
                                                });
                                                let required = required_pqc_key_kind(
                                                    self.method, self.op,
                                                );
                                                let candidates: Vec<SecretKey> = self
                                                    .secret_keys
                                                    .iter()
                                                    .filter(|entry| entry.method == self.method)
                                                    .filter(|entry| {
                                                        entry.kind.is_none()
                                                            || entry.kind == required
                                                    })
                                                    .cloned()
                                                    .collect();
                                                if candidates.is_empty() {
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "Noch kein {}-Schlüssel importiert.",
                                                            self.method.label()
                                                        ))
                                                        .size(11.0)
                                                        .color(egui::Color32::from_rgb(
                                                            105, 117, 130,
                                                        )),
                                                    );
                                                } else {
                                                    let selected = self
                                                        .key
                                                        .as_ref()
                                                        .and_then(|path| {
                                                            candidates
                                                                .iter()
                                                                .find(|entry| &entry.path == path)
                                                        })
                                                        .map_or(
                                                            "Schlüssel auswählen",
                                                            |entry| entry.label.as_str(),
                                                        );
                                                    egui::ComboBox::from_id_salt("secret_keys")
                                                        .selected_text(selected)
                                                        .show_ui(ui, |ui| {
                                                            for entry in &candidates {
                                                                if ui
                                                                    .selectable_label(
                                                                        self.key.as_ref()
                                                                            == Some(&entry.path),
                                                                        &entry.label,
                                                                    )
                                                                    .clicked()
                                                                {
                                                                    self.key = Some(
                                                                        entry.path.clone(),
                                                                    );
                                                                }
                                                            }
                                                        });
                                                }
                                                ui.horizontal(|ui| {
                                                    ui.add(
                                                        egui::TextEdit::singleline(
                                                            &mut self.secret_label,
                                                        )
                                                        .hint_text("Name, z. B. Anna oder Team"),
                                                    );
                                                    if ui.button("Importieren").clicked() {
                                                        self.import_secret_key();
                                                    }
                                                });
                                                if let Some(path) = &self.key {
                                                    ui.small(path.display().to_string());
                                                }
                                            }
                                            if self.op == Op::Verify {
                                                ui.add_space(10.0);
                                                ui.label("Signaturdatei");
                                                let shown = self.signature.clone().or_else(|| {
                                                    self.input
                                                        .as_deref()
                                                        .map(|input| default_signature(input, self.method))
                                                });
                                                ui.horizontal(|ui| {
                                                    ui.small(shown.map_or(
                                                        "Wird aus der Eingabedatei abgeleitet".to_owned(),
                                                        |path| path.display().to_string(),
                                                    ));
                                                    if ui.button("Wählen").clicked() {
                                                        if let Some(path) =
                                                            rfd::FileDialog::new().pick_file()
                                                        {
                                                            self.signature = Some(path);
                                                        }
                                                    }
                                                });
                                            }
                                        }

                                        if self.method.key_based() && self.text_mode && !self.keygen {
                                            ui.add_space(20.0);
                                            ui.label(if self.op == Op::Encrypt {
                                                "Klartext"
                                            } else {
                                                self.method.text_label()
                                            });
                                            ui.add(
                                                egui::TextEdit::multiline(&mut self.text_input)
                                                    .desired_rows(7)
                                                    .desired_width(f32::INFINITY),
                                            );
                                            if !self.text_output.is_empty() {
                                                ui.add_space(10.0);
                                                ui.label(if self.op == Op::Encrypt {
                                                    "Verschlüsselter Text"
                                                } else {
                                                    "Entschlüsselter Text"
                                                });
                                                ui.add(
                                                    egui::TextEdit::multiline(&mut self.text_output)
                                                        .desired_rows(7)
                                                        .desired_width(f32::INFINITY),
                                                );
                                            }
                                        } else if !self.keygen {
                                            ui.add_space(20.0);
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    egui::RichText::new("EINGABE")
                                                        .size(11.0)
                                                        .strong()
                                                        .color(egui::Color32::from_rgb(
                                                            99, 111, 125,
                                                        )),
                                                );
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        ui.label(
                                                            egui::RichText::new(
                                                                "Start › Datei oder Ordner öffnen",
                                                            )
                                                            .size(10.0)
                                                            .color(egui::Color32::from_rgb(
                                                                140, 150, 160,
                                                            )),
                                                        );
                                                    },
                                                );
                                            });
                                            ui.add_space(8.0);

// Datei- und Ordnerauswahl
ui.horizontal(|ui| {
    let text_active = self.method.key_based()
        && self.text_mode
        && !self.keygen
        && self.op.is_text_allowed();

    if ui
        .add_enabled(
            !self.running && !text_active,
            egui::Button::new("Datei wählen"),
        )
        .clicked()
    {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.input = Some(path);
            self.signature = None;
            self.status = "Datei ausgewählt.".into();
        }
    }

    if ui
        .add_enabled(
            !self.running && !text_active && self.op == Op::Encrypt,
            egui::Button::new("Ordner wählen"),
        )
        .clicked()
    {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            self.input = Some(path);
            self.signature = None;
            self.status = "Ordner ausgewählt.".into();
        }
    }

    if ui
        .add_enabled(
            !self.running && self.input.is_some(),
            egui::Button::new("Entfernen"),
        )
        .clicked()
    {
        self.input = None;
        self.signature = None;
        self.status = "Auswahl entfernt.".into();
    }
});

// Anzeige der aktuellen Auswahl
egui::Frame::new()
    .fill(egui::Color32::from_rgb(239, 242, 245))
    .corner_radius(egui::CornerRadius::same(9))
    .inner_margin(egui::Margin::symmetric(12, 12))
    .show(ui, |ui| {
        ui.set_width(ui.available_width());

        if let Some(path) = &self.input {
            let icon = if path.is_dir() {
                "Ordner:"
            } else {
                "Datei:"
            };

            ui.label(
                egui::RichText::new(icon)
                    .strong()
                    .color(ACCENT),
            );

            ui.add_space(3.0);

            ui.label(
                egui::RichText::new(path.display().to_string())
                    .size(12.0),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Keine Datei oder kein Ordner ausgewählt.")
                        .color(egui::Color32::from_rgb(115, 125, 137)),
                );
            });
        }
    });
}

                                        ui.add_space(18.0);
                                        let needs_password = !self.method.key_based()
                                            || self.op.uses_secret_key()
                                            || self.keygen;
                                        if needs_password {
                                            ui.label(
                                                egui::RichText::new("PASSWORT")
                                                    .size(11.0)
                                                    .strong()
                                                    .color(egui::Color32::from_rgb(99, 111, 125)),
                                            );
                                            ui.add_space(6.0);
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.password)
                                                    .password(true)
                                                    .hint_text(if self.keygen {
                                                        "Passphrase für den geheimen Schlüssel"
                                                    } else if self.op.uses_secret_key() {
                                                        "Passphrase des geheimen Schlüssels"
                                                    } else {
                                                        "Passwort eingeben"
                                                    })
                                                    .desired_width(f32::INFINITY),
                                            );
                                            if (self.method == Method::Ctx
                                                && self.op == Op::Encrypt)
                                                || (self.method.key_based() && self.keygen)
                                            {
                                                ui.add_space(7.0);
                                                ui.add(
                                                    egui::TextEdit::singleline(
                                                        &mut self.password_confirm,
                                                    )
                                                    .password(true)
                                                    .hint_text("Passphrase wiederholen")
                                                    .desired_width(f32::INFINITY),
                                                );
                                            }
                                            ui.add_space(5.0);
                                            ui.label(
                                                egui::RichText::new(
                                                    "Das Passwort wird nur für diesen Vorgang verwendet.",
                                                )
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(105, 117, 130)),
                                            );
                                        }
                                        ui.add_space(20.0);

                                        if self.running {
                                            if let Some(progress) = self.progress {
                                                let fraction = if progress.total == 0 {
                                                    1.0
                                                } else {
                                                    progress.done as f32 / progress.total as f32
                                                };
                                                ui.add(
                                                    egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                                                        .show_percentage(),
                                                );
                                            }
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    egui::RichText::new("Vorgang läuft …").color(
                                                        egui::Color32::from_rgb(24, 137, 112),
                                                    ),
                                                );
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        if ui.button("Abbrechen").clicked() {
                                                            if let Some(cancel) = &self.cancel {
                                                                cancel.store(
                                                                    true,
                                                                    Ordering::Relaxed,
                                                                );
                                                            }
                                                        }
                                                    },
                                                );
                                            });
                                        } else {
                                            let action = if self.method == Method::Pqc
                                                && self.keygen
                                            {
                                                "PQC-Schlüssel erstellen"
                                            } else if self.method.key_based() && self.keygen {
                                                "Schlüsselpaar erstellen"
                                            } else {
                                                self.op.action()
                                            };
                                            if ui
                                                .add_sized(
                                                    [ui.available_width(), 44.0],
                                                    egui::Button::new(
                                                        egui::RichText::new(action)
                                                            .strong()
                                                            .color(egui::Color32::WHITE),
                                                    )
                                                    .fill(egui::Color32::from_rgb(30, 135, 112)),
                                                )
                                                .clicked()
                                            {
                                                if self.method.key_based() && self.keygen {
                                                    self.generate_keys();
                                                } else {
                                                    self.start();
                                                }
                                            }
                                        }
                                        ui.add_space(8.0);
                                        ui.label(
                                            egui::RichText::new(&self.status)
                                                .size(12.0)
                                                .color(egui::Color32::from_rgb(76, 88, 102)),
                                        );
                                    },
                                );
                            });

                        ui.add_space(16.0);
                        ui.label(
                            egui::RichText::new(match self.method {
                                Method::Ctx => "CTX · Argon2id · XChaCha20-Poly1305",
                                Method::Pgp => {
                                    "OpenPGP · Ed25519 (Signatur) · X25519 · AES-256/OCB"
                                }
                                Method::Pqc => {
                                    "PQC · ML-KEM-768 · ML-DSA-65 · HKDF-SHA256 · XChaCha20-Poly1305"
                                }
                            })
                            .size(11.0)
                            .color(egui::Color32::from_rgb(104, 116, 130)),
                        );
                    });
                });
                }
            });

        if self.show_about {
            let mut close = false;
            egui::Window::new("Über cryptool")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ui.ctx(), |ui| {
                    ui.set_max_width(340.0);
                    ui.label(egui::RichText::new(format!("cryptool {VERSION}")).strong());
                    ui.label("Lokale Ver- und Entschlüsselung von Dateien und Text.");
                    ui.add_space(8.0);
                    ui.label("CTX · Argon2id · XChaCha20-Poly1305");
                    ui.label("OpenPGP · Ed25519 (Signatur) · X25519 · AES-256/OCB");
                    ui.label("PQC · ML-KEM-768 · ML-DSA-65 · HKDF-SHA256 · XChaCha20-Poly1305");
                    ui.add_space(10.0);
                    if ui.button("Schließen").clicked() {
                        close = true;
                    }
                });
            if close {
                self.show_about = false;
            }
        }
    }
}

const ACCENT: egui::Color32 = egui::Color32::from_rgb(24, 137, 112);

fn apply_visuals(ui: &mut egui::Ui) {
    let visuals = ui.visuals_mut();
    *visuals = egui::Visuals::light();
    visuals.panel_fill = egui::Color32::from_rgb(232, 235, 239);
    visuals.window_fill = egui::Color32::from_rgb(248, 249, 250);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(222, 226, 231);
    visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(41, 51, 63);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(205, 229, 223);
    visuals.widgets.hovered.fg_stroke.color = egui::Color32::from_rgb(28, 58, 53);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(184, 219, 210);
    visuals.widgets.active.fg_stroke.color = egui::Color32::from_rgb(24, 53, 48);
    visuals.selection.bg_fill = egui::Color32::from_rgb(111, 190, 170);
    visuals.selection.stroke.color = egui::Color32::from_rgb(28, 76, 66);
    visuals.override_text_color = Some(egui::Color32::from_rgb(38, 48, 59));
}

fn ribbon_tab(ui: &mut egui::Ui, selected: bool, text: &str) -> egui::Response {
    let font = egui::FontId::proportional(12.0);
    let width = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::WHITE)
        .size()
        .x
        .max(38.0)
        + 20.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 30.0), egui::Sense::click());
    let text_color = if selected {
        ACCENT
    } else if response.hovered() {
        egui::Color32::from_rgb(28, 38, 48)
    } else {
        egui::Color32::from_rgb(74, 85, 98)
    };
    if !selected && response.hovered() {
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(4),
            egui::Color32::from_rgb(238, 241, 244),
        );
    }
    if selected {
        let underline = egui::Rect::from_min_max(
            egui::pos2(rect.left() + 5.0, rect.bottom() - 2.5),
            egui::pos2(rect.right() - 5.0, rect.bottom()),
        );
        ui.painter()
            .rect_filled(underline, egui::CornerRadius::same(1), ACCENT);
    }
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, text_color);
    let position = rect.center() - galley.size() / 2.0;
    ui.painter().galley(position, galley, text_color);
    response
}

fn ribbon_button(
    ui: &mut egui::Ui,
    icon: RibbonIcon,
    label: &str,
    active: bool,
    enabled: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(78.0, 56.0),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let background = if !enabled {
        None
    } else if active {
        Some(egui::Color32::from_rgb(223, 242, 237))
    } else if response.hovered() {
        Some(egui::Color32::from_rgb(240, 243, 246))
    } else {
        None
    };
    if let Some(background) = background {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(7), background);
    }
    let color = if !enabled {
        egui::Color32::from_rgb(166, 175, 185)
    } else if active {
        ACCENT
    } else {
        egui::Color32::from_rgb(48, 58, 70)
    };
    draw_icon(
        ui.painter(),
        egui::pos2(rect.center().x, rect.top() + 18.0),
        icon,
        color,
    );
    let galley = ui.painter().layout(
        label.to_owned(),
        egui::FontId::proportional(9.5),
        color,
        rect.width() - 8.0,
    );
    let position = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.top() + 31.0);
    ui.painter().galley(position, galley, color);
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

#[derive(Clone, Copy)]
enum RibbonIcon {
    Lock,
    Unlock,
    Box,
    Key,
    KeyPlus,
    KeyOpen,
    File,
    Files,
    Folder,
    Text,
    Mail,
    Server,
    Shield,
    Signature,
    Check,
    Help,
}

fn draw_icon(painter: &egui::Painter, center: egui::Pos2, icon: RibbonIcon, color: egui::Color32) {
    let stroke = egui::Stroke::new(1.5, color);
    let origin = egui::pos2(center.x - 9.0, center.y - 9.0);
    let p = |x: f32, y: f32| egui::pos2(origin.x + x, origin.y + y);
    let line = |points: &[egui::Pos2]| {
        painter.add(egui::Shape::line(points.to_vec(), stroke));
    };

    match icon {
        RibbonIcon::Lock | RibbonIcon::Unlock => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(3.0, 9.0), p(15.0, 17.0)),
                egui::CornerRadius::same(2),
                stroke,
                egui::StrokeKind::Inside,
            );
            let sweep = if matches!(icon, RibbonIcon::Lock) {
                std::f32::consts::PI
            } else {
                std::f32::consts::PI - 0.6
            };
            let shackle: Vec<egui::Pos2> = (0..=14)
                .map(|i| {
                    let angle = std::f32::consts::PI + (i as f32 / 14.0) * sweep;
                    egui::pos2(
                        p(9.0, 9.0).x + 4.0 * angle.cos(),
                        p(9.0, 9.0).y + 4.0 * angle.sin(),
                    )
                })
                .collect();
            painter.add(egui::Shape::line(shackle, stroke));
            painter.circle_filled(p(9.0, 13.0), 1.3, color);
        }
        RibbonIcon::Box => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(3.0, 5.0), p(15.0, 16.0)),
                egui::CornerRadius::same(1),
                stroke,
                egui::StrokeKind::Inside,
            );
            line(&[p(3.0, 8.5), p(15.0, 8.5)]);
            line(&[p(9.0, 5.0), p(9.0, 16.0)]);
        }
        RibbonIcon::Key | RibbonIcon::KeyPlus | RibbonIcon::KeyOpen => {
            painter.circle_stroke(p(5.5, 5.5), 3.2, stroke);
            line(&[p(7.8, 7.8), p(15.0, 15.0)]);
            line(&[p(11.6, 11.6), p(13.4, 9.8)]);
            line(&[p(13.3, 13.3), p(15.1, 11.5)]);
            if matches!(icon, RibbonIcon::KeyPlus) {
                line(&[p(12.0, 2.0), p(12.0, 6.0)]);
                line(&[p(10.0, 4.0), p(14.0, 4.0)]);
            }
        }
        RibbonIcon::File => {
            line(&[
                p(5.0, 3.0),
                p(11.0, 3.0),
                p(14.0, 6.0),
                p(14.0, 15.0),
                p(5.0, 15.0),
                p(5.0, 3.0),
            ]);
            line(&[p(11.0, 3.0), p(11.0, 6.0), p(14.0, 6.0)]);
        }
        RibbonIcon::Files => {
            line(&[p(6.5, 3.0), p(12.0, 3.0), p(14.0, 5.0), p(14.0, 11.0)]);
            line(&[
                p(4.0, 5.5),
                p(9.5, 5.5),
                p(11.5, 7.5),
                p(11.5, 16.0),
                p(4.0, 16.0),
                p(4.0, 5.5),
            ]);
        }
        RibbonIcon::Folder => {
            line(&[
                p(3.0, 15.0),
                p(3.0, 5.0),
                p(8.0, 5.0),
                p(9.5, 7.5),
                p(15.0, 7.5),
                p(15.0, 15.0),
                p(3.0, 15.0),
            ]);
        }
        RibbonIcon::Text => {
            line(&[p(4.0, 5.0), p(14.0, 5.0)]);
            line(&[p(4.0, 9.0), p(14.0, 9.0)]);
            line(&[p(4.0, 13.0), p(10.0, 13.0)]);
        }
        RibbonIcon::Mail => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(3.0, 5.0), p(15.0, 14.0)),
                egui::CornerRadius::same(1),
                stroke,
                egui::StrokeKind::Inside,
            );
            line(&[p(3.0, 5.5), p(9.0, 10.0), p(15.0, 5.5)]);
        }
        RibbonIcon::Server => {
            for row in 0..3 {
                let top = 3.0 + row as f32 * 5.0;
                painter.rect_stroke(
                    egui::Rect::from_min_max(p(3.0, top), p(15.0, top + 4.0)),
                    egui::CornerRadius::same(1),
                    stroke,
                    egui::StrokeKind::Inside,
                );
                painter.circle_filled(p(12.0, top + 2.0), 0.7, color);
            }
        }
        RibbonIcon::Shield => {
            line(&[
                p(9.0, 2.0),
                p(15.0, 4.5),
                p(15.0, 9.5),
                p(9.0, 15.5),
                p(3.0, 9.5),
                p(3.0, 4.5),
                p(9.0, 2.0),
            ]);
            line(&[p(6.5, 8.0), p(9.0, 10.5), p(12.0, 6.0)]);
        }
        RibbonIcon::Signature => {
            // Stift über einer Linie: abgetrennte Signatur.
            line(&[p(3.5, 15.5), p(14.5, 15.5)]);
            line(&[
                p(4.0, 12.5),
                p(5.0, 8.5),
                p(12.5, 1.5),
                p(15.5, 4.5),
                p(8.0, 11.5),
                p(4.0, 12.5),
            ]);
            line(&[p(5.0, 8.5), p(8.0, 11.5)]);
        }
        RibbonIcon::Check => {
            painter.circle_stroke(p(9.0, 9.0), 6.5, stroke);
            line(&[p(5.5, 9.5), p(8.0, 12.0), p(12.5, 6.5)]);
        }
        RibbonIcon::Help => {
            painter.circle_stroke(p(9.0, 9.0), 6.5, stroke);
            painter.text(
                p(9.0, 9.0),
                egui::Align2::CENTER_CENTER,
                "?",
                egui::FontId::proportional(10.0),
                color,
            );
        }
    }
}

fn ribbon_group(ui: &mut egui::Ui, title: &str, contents: impl FnOnce(&mut egui::Ui)) {
    ui.vertical(|ui| {
        ui.set_min_height(70.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            contents(ui);
        });
        let width = ui.min_rect().width().max(24.0);
        ui.allocate_ui_with_layout(
            egui::vec2(width, 14.0),
            egui::Layout::top_down(egui::Align::Center),
            |ui| {
                ui.label(
                    egui::RichText::new(title)
                        .size(9.0)
                        .color(egui::Color32::from_rgb(128, 139, 150)),
                );
            },
        );
    });
}

fn ribbon_separator(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 56.0), egui::Sense::hover());
    ui.painter().vline(
        rect.center().x,
        rect.y_range(),
        egui::Stroke::new(1.0, egui::Color32::from_rgb(226, 230, 235)),
    );
}

fn recipient_key_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("APPDATA").or_else(|| std::env::var_os("LOCALAPPDATA"));
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let root = std::env::var_os("XDG_CONFIG_HOME").or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").into_os_string())
    });
    root.map(|path| PathBuf::from(path).join("cryptool").join("recipient-keys"))
}

fn secret_key_dir() -> Option<PathBuf> {
    recipient_key_dir().map(|path| path.with_file_name("secret-keys"))
}

const KEYSERVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const KEYSERVER_MAX_BYTES: u64 = 4 * 1024 * 1024;

const DEFAULT_KEYSERVER_URL: &str = "http://localhost:8080";

/// Speicherort der zuletzt verwendeten Keyserver-Adresse.
fn keyserver_config_path() -> Option<PathBuf> {
    recipient_key_dir().map(|path| path.with_file_name("keyserver-url.txt"))
}

fn select_keyserver_url(env: Option<&str>, saved: Option<&str>) -> String {
    env.map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| saved.map(str::trim).filter(|value| !value.is_empty()))
        .unwrap_or(DEFAULT_KEYSERVER_URL)
        .to_owned()
}

/// Lädt die Adresse: Umgebungsvariable hat Vorrang, danach die zuletzt
/// gespeicherte Adresse, sonst der Standardwert.
fn load_keyserver_url() -> String {
    let env = std::env::var("CRYPTOOL_KEYSERVER_URL").ok();
    let saved = keyserver_config_path().and_then(|path| fs::read_to_string(path).ok());
    select_keyserver_url(env.as_deref(), saved.as_deref())
}

fn save_keyserver_url(url: &str) {
    let Some(path) = keyserver_config_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{url}\n"));
}

/// Ergänzt ein fehlendes Schema und entfernt einen abschließenden Schrägstrich.
fn normalize_keyserver_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    let normalized = if lower.starts_with("http://") || lower.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    };
    if keyserver_url_allowed(&normalized) {
        normalized
    } else {
        String::new()
    }
}

fn keyserver_url_allowed(url: &str) -> bool {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if scheme == "https" {
        return true;
    }
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or("")
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn fetch_keyserver_list(base: &str) -> Result<Vec<KeyserverEntry>, String> {
    let url = format!("{base}/list");
    let response = ureq::get(&url)
        .timeout(KEYSERVER_TIMEOUT)
        .call()
        .map_err(|error| format!("Keyserver nicht erreichbar ({url}): {error}"))?;
    let mut body = String::new();
    response
        .into_reader()
        .take(KEYSERVER_MAX_BYTES)
        .read_to_string(&mut body)
        .map_err(|error| format!("Antwort konnte nicht gelesen werden: {error}"))?;
    Ok(parse_keyserver_list(&body))
}

fn fetch_keyserver_key(base: &str, id: u64) -> Result<Vec<u8>, String> {
    let url = format!("{base}/download/{id}");
    let response = ureq::get(&url)
        .timeout(KEYSERVER_TIMEOUT)
        .call()
        .map_err(|error| format!("Schlüssel konnte nicht geladen werden ({url}): {error}"))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(KEYSERVER_MAX_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Antwort konnte nicht gelesen werden: {error}"))?;
    if bytes.is_empty() {
        return Err("Der Keyserver hat eine leere Datei geliefert.".into());
    }
    Ok(bytes)
}

/// Liest die HTML-Tabelle von `/list`. Der Keyserver liefert bewusst nur HTML;
/// deshalb werden die Zeilen und Zellen hier minimal ausgewertet.
fn parse_keyserver_list(html: &str) -> Vec<KeyserverEntry> {
    let mut entries: Vec<KeyserverEntry> = Vec::new();

    let lower = html.to_ascii_lowercase();
    let mut rest = lower.as_str();
    let mut offset = 0;
    while let Some(start_rel) = rest.find("<tr") {
        let start = offset + start_rel;
        rest = &rest[start_rel + 3..];
        offset = start + 3;
        let Some(end_rel) = rest.find("</tr>") else {
            break;
        };
        let end = offset + end_rel;
        let row = &html[start..end];
        let cells = parse_keyserver_cells(row);
        let id_cell = cells.iter().position(|cell| cell.parse::<u64>().is_ok());
        let id = id_cell
            .and_then(|index| cells[index].parse::<u64>().ok())
            .or_else(|| extract_keyserver_download_id(row));
        if let Some(id) = id {
            let data_start = id_cell.map_or(0, |index| index + 1);
            let data: Vec<String> = cells[data_start..]
                .iter()
                .filter(|cell| {
                    !cell.is_empty()
                        && !cell.eq_ignore_ascii_case("download")
                        && !is_keyserver_method_cell(cell)
                })
                .cloned()
                .collect();
            let owner = data
                .first()
                .map(|value| clean_keyserver_owner(value))
                .unwrap_or_default();
            let filename = data
                .get(1)
                .cloned()
                .filter(|value| value != "-")
                .unwrap_or_default();
            let method = infer_keyserver_method(&cells);
            if !entries.iter().any(|entry| entry.id == id) {
                entries.push(KeyserverEntry {
                    id,
                    owner: if owner.is_empty() {
                        nearby_keyserver_label(html, "", id)
                    } else {
                        owner
                    },
                    filename,
                    method,
                });
            }
        }
        rest = &rest[end_rel + 5..];
        offset = end + 5;
    }

    // Einige Keyserver-Ansichten zeigen Download-Links statt einer einfachen
    // Tabelle mit numerischer ID-Spalte. Die IDs lassen sich direkt aus den
    // stabilen `/download/<id>`-Links gewinnen.
    if entries.is_empty() {
        let mut rest = lower.as_str();
        while let Some(link) = rest.find("/download/") {
            rest = &rest[link + "/download/".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(id) = digits.parse::<u64>() {
                if !entries.iter().any(|entry| entry.id == id) {
                    entries.push(KeyserverEntry {
                        id,
                        owner: nearby_keyserver_label(html, rest, id),
                        filename: String::new(),
                        method: None,
                    });
                }
            }
        }
    }
    entries
}

fn infer_keyserver_method(cells: &[String]) -> Option<Method> {
    let description = cells.join(" ").to_ascii_lowercase();
    if ["pqc", "ml-kem", "ml-dsa", ".pem", ".pqc"]
        .iter()
        .any(|marker| description.contains(marker))
        || description
            .split_whitespace()
            .any(|word| matches!(word, "kem" | "dsa"))
    {
        Some(Method::Pqc)
    } else if ["openpgp", "pgp", ".asc", ".gpg", ".pgp"]
        .iter()
        .any(|marker| description.contains(marker))
    {
        Some(Method::Pgp)
    } else {
        None
    }
}

fn is_keyserver_method_cell(cell: &str) -> bool {
    matches!(
        cell.trim().to_ascii_lowercase().as_str(),
        "openpgp" | "pgp" | "pqc" | "kem" | "dsa" | "ml-kem-768" | "ml-dsa-65"
    )
}

fn clean_keyserver_owner(owner: &str) -> String {
    let mut owner = owner.trim();
    for prefix in ["OpenPGP", "PGP", "PQC", "ML-KEM-768", "ML-DSA-65"] {
        if owner
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        {
            owner = owner[prefix.len()..].trim_start_matches([' ', ':', '-', '·']);
            break;
        }
    }
    owner.trim().to_owned()
}

fn keyserver_entry_matches_method(entry: &KeyserverEntry, method: Method) -> bool {
    match entry.method {
        Some(entry_method) => entry_method == method,
        // Alte Keyserver-Listen enthalten nur OpenPGP-Einträge ohne explizite
        // Kennzeichnung. Diese bleiben im OpenPGP-Modus sichtbar.
        None => method == Method::Pgp,
    }
}

fn parse_keyserver_cells(row: &str) -> Vec<String> {
    let lower = row.to_ascii_lowercase();
    let mut cells = Vec::new();
    let mut rest = lower.as_str();
    let mut offset = 0;
    while let Some(start_rel) = rest.find("<td") {
        let start = offset + start_rel;
        rest = &rest[start_rel + 3..];
        offset = start + 3;
        let Some(content_start_rel) = rest.find('>') else {
            break;
        };
        let content_start = offset + content_start_rel + 1;
        rest = &rest[content_start_rel + 1..];
        offset = content_start;
        let Some(end_rel) = rest.find("</td>") else {
            break;
        };
        let end = offset + end_rel;
        cells.push(html_unescape(
            strip_html_tags(&row[content_start..end]).trim(),
        ));
        rest = &rest[end_rel + 5..];
        offset = end + 5;
    }
    cells
}

fn extract_keyserver_download_id(html: &str) -> Option<u64> {
    let lower = html.to_ascii_lowercase();
    let link = lower.find("/download/")? + "/download/".len();
    let digits: String = lower[link..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn nearby_keyserver_label(html: &str, _remaining: &str, id: u64) -> String {
    let lower = html.to_ascii_lowercase();
    let link = format!("/download/{id}");
    let Some(link_at) = lower.find(&link) else {
        return format!("Schlüssel {id}");
    };

    let mut block: Option<(usize, &'static str)> = None;
    for tag in ["li", "tr", "article", "p", "div"] {
        let marker = format!("<{tag}");
        if let Some(start) = lower[..link_at].rfind(&marker) {
            if block.is_none_or(|(previous, _)| start > previous) {
                block = Some((start, tag));
            }
        }
    }
    let Some((start, tag)) = block else {
        return format!("Schlüssel {id}");
    };
    let end = lower[link_at..]
        .find(&format!("</{tag}>"))
        .map(|offset| link_at + offset)
        .unwrap_or(html.len());
    let visible = html_unescape(strip_html_tags(&html[start..end]).trim());
    let visible = visible
        .split_whitespace()
        .filter(|word| {
            !word.eq_ignore_ascii_case("download")
                && !word.eq_ignore_ascii_case("herunterladen")
                && *word != id.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let visible = clean_keyserver_owner(&visible);
    if visible.is_empty() {
        format!("Schlüssel {id}")
    } else {
        visible
    }
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

/// Entfernt HTML-Markup aus Tabellenzellen, etwa wenn der Server die ID als
/// Link (`<a href="/download/7">7</a>`) ausgibt.
fn strip_html_tags(input: &str) -> String {
    let mut text = String::with_capacity(input.len());
    let mut in_tag = false;
    for character in input.chars() {
        match character {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text
}

fn method_from_tag(tag: &str) -> Option<Method> {
    match tag {
        "pgp" => Some(Method::Pgp),
        "pqc" => Some(Method::Pqc),
        _ => None,
    }
}

/// Erkennt anhand des Dateiinhalts, zu welchem Verfahren ein Schlüssel gehört.
/// Das ist nötig, weil alte Einträge in `recipients.tsv` noch kein Verfahren
/// gespeichert haben und weil beim Auswählen eines geheimen Schlüssels geprüft
/// werden soll, ob er zum aktiven Verfahren passt.
fn detect_key_method_bytes(bytes: &[u8]) -> Option<Method> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let bytes = &bytes[start..];
    if bytes.starts_with(b"-----BEGIN PGP ") {
        return Some(Method::Pgp);
    }
    // Standardisierte PQC-Schlüssel: SPKI (`PUBLIC KEY`) bzw. PKCS#8
    // (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`) als PEM oder DER. Der
    // Algorithmus (ML-KEM/ML-DSA) steht in der OID und wird beim Import
    // gesondert bestimmt.
    if bytes.starts_with(b"-----BEGIN CRYPTOOL PQC ")
        || bytes.starts_with(b"CTPK")
        || bytes.starts_with(b"CTSK")
        || bytes.starts_with(b"-----BEGIN PUBLIC KEY-----")
        || bytes.starts_with(b"-----BEGIN PRIVATE KEY-----")
        || bytes.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || bytes.first() == Some(&0x30)
    {
        return Some(Method::Pqc);
    }
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Some(Method::Pgp);
    }
    None
}

fn detect_key_method(path: &Path) -> Option<Method> {
    detect_key_method_bytes(&fs::read(path).ok()?).or_else(|| {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(|extension| match extension {
                "pqc" => Some(Method::Pqc),
                "asc" | "pgp" => Some(Method::Pgp),
                _ => None,
            })
    })
}

fn load_recipient_keys() -> Vec<RecipientKey> {
    let Some(directory) = recipient_key_dir() else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(directory.join("recipients.tsv")) else {
        return Vec::new();
    };
    let mut recipients = Vec::new();
    for line in contents.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        let (method, kind_tag, label, file_name) = match parts.as_slice() {
            // Neues Format: Verfahren, Schlüsselart (kem/dsa/-), Name, Datei.
            [tag, kind, label, file_name] => {
                let Some(method) = method_from_tag(tag) else {
                    continue;
                };
                (Some(method), *kind, *label, *file_name)
            }
            // Früheres Format ohne Schlüsselart.
            [tag, label, file_name] => {
                let Some(method) = method_from_tag(tag) else {
                    continue;
                };
                (Some(method), "-", *label, *file_name)
            }
            // Altes Format ohne Verfahren: anhand des Schlüsseldatei-Inhalts
            // zuordnen; alte Einträge waren in der Regel OpenPGP.
            [label, file_name] => (None, "-", *label, *file_name),
            _ => continue,
        };
        let file_name = PathBuf::from(file_name);
        if file_name.components().count() != 1 {
            continue;
        }
        let path = directory.join(file_name);
        if !path.is_file() {
            continue;
        }
        let Some(method) = method.or_else(|| detect_key_method(&path)) else {
            continue;
        };
        // Bei PQC-Schlüsseln steckt die Unterart in der OID. Ältere Einträge
        // haben keine Angabe; dann wird sie aus der Datei nachbestimmt.
        let kind = if method == Method::Pqc {
            pqc_kind_from_tag(kind_tag).or_else(|| {
                let bytes = fs::read(&path).ok()?;
                pqc_detect_public_key_kind(&bytes).ok()
            })
        } else {
            None
        };
        let kind = kind.filter(|kind| kind.is_public());
        recipients.push(RecipientKey {
            label: label.to_owned(),
            path,
            method,
            kind,
        });
    }
    recipients
}

fn load_secret_keys() -> Vec<SecretKey> {
    let Some(directory) = secret_key_dir() else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(directory.join("secret-keys.tsv")) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for line in contents.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        let (method, kind_tag, label, file_name) = match parts.as_slice() {
            [tag, kind, label, file_name] => {
                let Some(method) = method_from_tag(tag) else {
                    continue;
                };
                (method, *kind, *label, *file_name)
            }
            [tag, label, file_name] => {
                let Some(method) = method_from_tag(tag) else {
                    continue;
                };
                (method, "-", *label, *file_name)
            }
            _ => continue,
        };
        let file_name = PathBuf::from(file_name);
        if file_name.components().count() != 1 {
            continue;
        }
        let path = directory.join(file_name);
        if !path.is_file() {
            continue;
        }
        // Verschlüsselte PKCS#8-Dateien verraten ihre Unterart erst nach dem
        // Entschlüsseln; daher wird die gespeicherte Angabe bzw. der Dateiname
        // verwendet.
        let kind = if method == Method::Pqc {
            secret_kind_from_tag(kind_tag).or_else(|| secret_kind_from_name(&path))
        } else {
            None
        };
        let kind = kind.filter(|kind| kind.is_secret());
        keys.push(SecretKey {
            label: (*label).to_owned(),
            path,
            method,
            kind,
        });
    }
    keys
}

fn run_operation(
    input: PathBuf,
    output: PathBuf,
    signature: Option<PathBuf>,
    key: Option<PathBuf>,
    password: SecretString,
    op: Op,
    method: Method,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    let mut on_progress = |progress| {
        let _ = events.send(Event::Progress(progress));
    };
    let result = match (method, op) {
        (Method::Ctx, Op::Encrypt) => {
            encrypt_path(&input, &output, password, false, &mut on_progress, &cancel)
                .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Ctx, Op::Decrypt) => {
            decrypt_path(&input, &output, password, false, &mut on_progress, &cancel)
                .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Ctx, Op::Sign | Op::Verify) => unreachable!("CTX unterstützt keine Signaturen"),
        (Method::Pgp, Op::Encrypt) => {
            let key = key.expect("OpenPGP-Operation benötigt einen Schlüssel");
            pgp_encrypt_path(
                &input,
                &output,
                &key,
                false,
                false,
                &mut on_progress,
                &cancel,
            )
            .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Pgp, Op::Decrypt) => {
            let key = key.expect("OpenPGP-Operation benötigt einen Schlüssel");
            pgp_decrypt_path(
                &input,
                &output,
                &key,
                password,
                false,
                &mut on_progress,
                &cancel,
            )
            .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Pgp, Op::Sign) => {
            let key = key.expect("OpenPGP-Operation benötigt einen Schlüssel");
            pgp_sign_path(
                &input,
                &output,
                &key,
                password,
                false,
                false,
                &mut on_progress,
                &cancel,
            )
            .map(|_| format!("Signiert: {}", output.display()))
        }
        (Method::Pgp, Op::Verify) => {
            let key = key.expect("OpenPGP-Operation benötigt einen Schlüssel");
            let signature = signature.expect("Signaturprüfung benötigt eine Signaturdatei");
            pgp_verify_path(&input, &signature, &key, &mut on_progress, &cancel)
                .map(|report| verify_message(&report))
        }
        (Method::Pqc, Op::Encrypt) => {
            let key = key.expect("PQC-Operation benötigt einen Schlüssel");
            pqc_encrypt_path(&input, &output, &key, false, &mut on_progress, &cancel)
                .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Pqc, Op::Decrypt) => {
            let key = key.expect("PQC-Operation benötigt einen Schlüssel");
            pqc_decrypt_path(
                &input,
                &output,
                &key,
                password,
                false,
                &mut on_progress,
                &cancel,
            )
            .map(|_| format!("Fertig: {}", output.display()))
        }
        (Method::Pqc, Op::Sign) => {
            let key = key.expect("PQC-Operation benötigt einen Schlüssel");
            pqc_sign_path(
                &input,
                &output,
                &key,
                password,
                false,
                false,
                &mut on_progress,
                &cancel,
            )
            .map(|_| format!("Signiert: {}", output.display()))
        }
        (Method::Pqc, Op::Verify) => {
            let key = key.expect("PQC-Operation benötigt einen Schlüssel");
            let signature = signature.expect("Signaturprüfung benötigt eine Signaturdatei");
            pqc_verify_path(&input, &signature, &key, &mut on_progress, &cancel)
                .map(|report| verify_message(&report))
        }
    };
    let message = result.map_err(|error| error.to_string());
    let _ = events.send(Event::Finished(message));
}

fn verify_message(report: &VerifyReport) -> String {
    match report.created {
        Some(seconds) => format!(
            "Signatur gültig. Unterzeichner: {} · Schlüssel: {} · Zeitpunkt: {seconds} (Unix-Zeit)",
            report.signer, report.key_id
        ),
        None => format!(
            "Signatur gültig. Unterzeichner: {} · Schlüssel: {}",
            report.signer, report.key_id
        ),
    }
}

fn append_extension(input: &Path, extension: &str) -> PathBuf {
    let mut name = input.as_os_str().to_owned();
    name.push(format!(".{extension}"));
    PathBuf::from(name)
}

fn default_output(input: &Path, op: Op, method: Method) -> PathBuf {
    match op {
        Op::Encrypt => append_extension(input, method.extension()),
        Op::Sign => append_extension(input, method.signature_extension()),
        Op::Verify => default_signature(input, method),
        Op::Decrypt => {
            let name = input.file_name().unwrap_or_default().to_os_string();
            let text = name.to_string_lossy();
            let suffix = format!(".{}", method.extension());
            let base = text
                .strip_suffix(&suffix)
                .or_else(|| text.strip_suffix(&format!(".{}.asc", method.extension())))
                .unwrap_or(&text);
            if base.ends_with(".tar.zst") {
                input.with_file_name(base.trim_end_matches(".tar.zst"))
            } else if base == text {
                let mut name = input.as_os_str().to_owned();
                name.push(".dec");
                PathBuf::from(name)
            } else {
                input.with_file_name(base)
            }
        }
    }
}

/// Sucht die Standard-Signaturdatei; bevorzugt die binäre Variante und fällt
/// bei Bedarf auf ASCII-Armor zurück.
fn default_signature(input: &Path, method: Method) -> PathBuf {
    let binary = append_extension(input, method.signature_extension());
    if binary.exists() {
        return binary;
    }
    let armored = append_extension(input, method.signature_armor_extension());
    if armored.exists() {
        armored
    } else {
        binary
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 950.0])
            .with_resizable(false)
            .with_maximize_button(false)
            .with_maximized(false)
            .with_fullscreen(false),
        ..Default::default()
    };
    eframe::run_native(
        &format!("cryptool {VERSION}"),
        options,
        Box::new(|_creation_context| Ok(Box::<CryptoolApp>::default())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keyserver_list() {
        let html = r#"
            <table>
              <tr><th>ID</th><th>Kennung</th><th>Dateiname</th><th>Download</th></tr>
              <tr>
                <td>7</td>
                <td>Anna &amp; Co Beispiel</td>
                <td>anna.asc</td>
                <td><a href="/download/7">Download</a></td>
              </tr>
              <tr><td colspan="4" style="text-align:center;">Keine Keys vorhanden.</td></tr>
            </table>
        "#;
        let entries = parse_keyserver_list(html);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 7);
        assert_eq!(entries[0].owner, "Anna & Co Beispiel");
        assert_eq!(entries[0].filename, "anna.asc");
    }

    #[test]
    fn parses_missing_filename_as_empty() {
        let html = "<tr><td>1</td><td>Anna</td><td>-</td></tr>";
        let entries = parse_keyserver_list(html);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].filename.is_empty());
    }

    #[test]
    fn normalizes_keyserver_url() {
        assert_eq!(
            normalize_keyserver_url("localhost:8080/"),
            "http://localhost:8080"
        );
        assert_eq!(
            normalize_keyserver_url("https://keys.example.org/"),
            "https://keys.example.org"
        );
        assert_eq!(normalize_keyserver_url("  "), "");
    }

    #[test]
    fn selects_keyserver_url_prefers_env_then_saved() {
        assert_eq!(
            select_keyserver_url(Some(" https://env.example "), Some("https://saved.example")),
            "https://env.example"
        );
        assert_eq!(
            select_keyserver_url(None, Some(" https://saved.example\n")),
            "https://saved.example"
        );
        assert_eq!(
            select_keyserver_url(Some("  "), None),
            DEFAULT_KEYSERVER_URL
        );
        assert_eq!(select_keyserver_url(None, None), DEFAULT_KEYSERVER_URL);
    }

    #[test]
    fn fetches_keyserver_list_over_http() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(
                request.starts_with("GET /list "),
                "unerwartete Anfrage: {request}"
            );
            let body = "<tr><td>7</td><td>Anna</td><td>anna.asc</td></tr>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let entries = fetch_keyserver_list(&format!("http://{address}")).unwrap();
        server.join().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 7);
        assert_eq!(entries[0].owner, "Anna");
    }

    #[test]
    fn fetches_keyserver_key_over_http() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(
                request.starts_with("GET /download/7 "),
                "unerwartete Anfrage: {request}"
            );
            let body = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let bytes = fetch_keyserver_key(&format!("http://{address}"), 7).unwrap();
        server.join().unwrap();
        assert_eq!(bytes, b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
    }
}
