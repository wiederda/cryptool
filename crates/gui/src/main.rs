#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use cryptool_lib::{
    decrypt_path, encrypt_path, pgp_decrypt_path, pgp_decrypt_text, pgp_encrypt_path,
    pgp_encrypt_text, pgp_generate_key, pqc_decrypt_path, pqc_decrypt_text, pqc_encrypt_path,
    pqc_encrypt_text, pqc_generate_key, Progress, SecretString,
};
use eframe::egui;
use zeroize::Zeroize;

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

#[derive(Clone)]
struct RecipientKey {
    label: String,
    path: PathBuf,
    method: Method,
}

struct CryptoolApp {
    input: Option<PathBuf>,
    key: Option<PathBuf>,
    recipients: Vec<RecipientKey>,
    recipient_label: String,
    method: Method,
    keygen: bool,
    text_mode: bool,
    text_input: String,
    text_output: String,
    user_id: String,
    password: String,
    password_confirm: String,
    encrypting: bool,
    running: bool,
    progress: Option<Progress>,
    status: String,
    cancel: Option<Arc<AtomicBool>>,
    events: Option<Receiver<Event>>,
    ribbon_tab: RibbonTab,
    show_about: bool,
}

impl Default for CryptoolApp {
    fn default() -> Self {
        Self {
            input: None,
            key: None,
            recipients: load_recipient_keys(),
            recipient_label: String::new(),
            method: Method::Ctx,
            keygen: false,
            text_mode: false,
            text_input: String::new(),
            text_output: String::new(),
            user_id: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            encrypting: true,
            running: false,
            progress: None,
            status: "Datei oder Ordner auswählen".into(),
            cancel: None,
            events: None,
            ribbon_tab: RibbonTab::Start,
            show_about: false,
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
        let Some(directory) = recipient_key_dir() else {
            self.status = "Der Speicherort für Schlüssel ist nicht verfügbar.".into();
            return;
        };
        if let Err(error) = fs::create_dir_all(&directory) {
            self.status = format!("Schlüsselordner konnte nicht angelegt werden: {error}");
            return;
        }
        let next_id = (1u64..)
            .find(|id| !directory.join(format!("recipient-{id}.key")).exists())
            .unwrap_or(1);
        let file_name = format!("recipient-{next_id}.key");
        let destination = directory.join(&file_name);
        if let Err(error) = fs::copy(&source, &destination) {
            self.status = format!("Schlüssel konnte nicht importiert werden: {error}");
            return;
        }
        let manifest = directory.join("recipients.tsv");
        let mut contents = fs::read_to_string(&manifest).unwrap_or_default();
        contents.push_str(&format!("{}\t{}\t{}\n", method.tag(), label, file_name));
        if let Err(error) = fs::write(&manifest, contents) {
            let _ = fs::remove_file(&destination);
            self.status = format!("Schlüsselverwaltung konnte nicht gespeichert werden: {error}");
            return;
        }
        self.recipients.push(RecipientKey {
            label: label.clone(),
            path: destination.clone(),
            method,
        });
        self.key = Some(destination);
        self.recipient_label.clear();
        self.status = format!("Öffentlicher Schlüssel für {label} importiert.");
    }

    fn set_mode(&mut self, encrypting: bool) {
        if self.running || self.encrypting == encrypting {
            return;
        }
        self.encrypting = encrypting;
        self.input = None;
        self.password.zeroize();
        self.password_confirm.zeroize();
        self.progress = None;
        self.status = if encrypting {
            "Datei oder Ordner auswählen".into()
        } else {
            format!("{}: Datei zum Entschlüsseln auswählen", self.method.label())
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
        self.password.zeroize();
        self.password_confirm.zeroize();
        self.progress = None;
        self.status = "Datei oder Ordner auswählen".into();
    }

    fn generate_keys(&mut self) {
        if self.user_id.trim().is_empty() {
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
        let (secret_name, public_name) = match self.method {
            Method::Pgp => ("schluessel.sec.asc", "schluessel.pub.asc"),
            Method::Pqc => ("schluessel.sec.pqc", "schluessel.pub.pqc"),
            Method::Ctx => return,
        };
        let Some(secret_out) = rfd::FileDialog::new()
            .set_file_name(secret_name)
            .save_file()
        else {
            return;
        };
        let Some(public_out) = rfd::FileDialog::new()
            .set_file_name(public_name)
            .save_file()
        else {
            return;
        };
        if secret_out == public_out {
            self.status = "Geheimer und öffentlicher Schlüssel benötigen getrennte Dateien.".into();
            return;
        }
        let mut password = std::mem::take(&mut self.password);
        self.password_confirm.zeroize();
        let passphrase = SecretString::new(std::mem::take(&mut password));
        password.zeroize();
        let user_id = self.user_id.trim().to_owned();
        let method = self.method;
        self.running = true;
        self.status = "Schlüsselpaar wird erzeugt …".into();
        let (tx, rx) = mpsc::channel();
        self.events = Some(rx);
        thread::spawn(move || {
            let result = match method {
                Method::Pgp => {
                    pgp_generate_key(&user_id, passphrase, &secret_out, &public_out, false)
                }
                Method::Pqc => {
                    pqc_generate_key(&user_id, passphrase, &secret_out, &public_out, false)
                }
                Method::Ctx => unreachable!("CTX erzeugt keine Schlüsselpaare"),
            }
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

    fn start(&mut self) {
        if self.method.key_based() && self.text_mode {
            self.start_text();
            return;
        }
        let Some(input) = self.input.clone() else {
            self.status = "Bitte zuerst eine Eingabe auswählen.".into();
            return;
        };
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
        if (!self.method.key_based() || !self.encrypting) && self.password.is_empty() {
            self.status = "Bitte ein Passwort eingeben.".into();
            return;
        }
        if !self.method.key_based() && self.encrypting && self.password != self.password_confirm {
            self.status = "Die Passwörter stimmen nicht überein.".into();
            return;
        }

        let mut password = std::mem::take(&mut self.password);
        self.password_confirm.zeroize();
        let secret = SecretString::new(std::mem::take(&mut password));
        password.zeroize();
        let encrypting = self.encrypting;
        let method = self.method;
        let output = default_output(&input, encrypting, method);
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
                key,
                secret,
                encrypting,
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
        if !self.encrypting && self.password.is_empty() {
            self.status = "Bitte die Passphrase des geheimen Schlüssels eingeben.".into();
            return;
        }
        let input = std::mem::take(&mut self.text_input);
        let passphrase = SecretString::new(std::mem::take(&mut self.password));
        self.password_confirm.zeroize();
        self.running = true;
        self.status = "Text wird verarbeitet …".into();
        self.text_output.clear();
        let (tx, rx) = mpsc::channel();
        self.events = Some(rx);
        let encrypting = self.encrypting;
        let method = self.method;
        thread::spawn(move || {
            let result = match method {
                Method::Pgp => {
                    if encrypting {
                        pgp_encrypt_text(&input, &key)
                    } else {
                        pgp_decrypt_text(&input, &key, passphrase)
                    }
                }
                Method::Pqc => {
                    if encrypting {
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
        let Some(events) = &self.events else { return };
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
        if self.running {
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
            format!(
                "{name} · Text {}",
                if self.encrypting {
                    "verschlüsseln"
                } else {
                    "entschlüsseln"
                }
            )
        } else if self.method == Method::Ctx {
            format!(
                "CTX · {}",
                if self.encrypting {
                    "Verschlüsseln"
                } else {
                    "Entschlüsseln"
                }
            )
        } else {
            format!(
                "{name} · Datei {}",
                if self.encrypting {
                    "verschlüsseln"
                } else {
                    "entschlüsseln"
                }
            )
        }
    }

    fn subtitle(&self) -> String {
        if self.method.key_based() && self.keygen {
            format!("{}-Schlüsselpaar erzeugen.", self.method.label())
        } else if self.method.key_based() && self.text_mode {
            "Text verschlüsseln oder entschlüsseln.".to_owned()
        } else if self.encrypting {
            "Datei oder Ordner auswählen und verschlüsseln.".to_owned()
        } else {
            "Datei oder Ordner auswählen und entschlüsseln.".to_owned()
        }
    }

    fn start_ribbon(&mut self, ui: &mut egui::Ui) {
        ribbon_group(ui, "Eingabe", |ui| {
            let text_active = self.method.key_based() && self.text_mode && !self.keygen;
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
                }
            }
            let folder_available = !self.running && !text_active && self.encrypting;
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
                self.encrypting,
                available,
            )
            .clicked()
            {
                self.set_mode(true);
            }
            if ribbon_button(
                ui,
                RibbonIcon::Unlock,
                "Entschlüsseln",
                !self.encrypting,
                available,
            )
            .clicked()
            {
                self.set_mode(false);
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
            let text_available = self.method.key_based() && !self.keygen && !self.running;
            if ribbon_button(ui, RibbonIcon::Text, "Text", self.text_mode, text_available).clicked()
            {
                self.text_mode = true;
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
            }
        });
    }

    fn keys_ribbon(&mut self, ui: &mut egui::Ui) {
        ribbon_group(ui, "Schlüsselpaar", |ui| {
            let available = self.method.key_based() && !self.running;
            let create =
                ribbon_button(ui, RibbonIcon::KeyPlus, "Erstellen", self.keygen, available);
            if create.clicked() {
                self.keygen = true;
                self.password.zeroize();
                self.password_confirm.zeroize();
                self.status = "Nutzerkennung und Passphrase eingeben.".into();
            }
            let process =
                ribbon_button(ui, RibbonIcon::Mail, "Verarbeiten", !self.keygen, available);
            if process.clicked() {
                self.keygen = false;
                self.password.zeroize();
                self.password_confirm.zeroize();
                self.status = "Datei oder Ordner auswählen".into();
            }
        });
        ribbon_separator(ui);
        ribbon_group(ui, "Geheimer Schlüssel", |ui| {
            let available = self.method.key_based() && !self.encrypting && !self.running;
            if ribbon_button(ui, RibbonIcon::KeyOpen, "Öffnen", false, available).clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    match detect_key_method(&path) {
                        Some(method) if method == self.method => {
                            self.key = Some(path);
                            self.status =
                                format!("{}: geheimer Schlüssel ausgewählt.", self.method.label());
                        }
                        Some(method) => {
                            self.status = format!(
                                "Die Datei enthält einen {}-Schlüssel, nicht {}.",
                                method.label(),
                                self.method.label()
                            );
                        }
                        None => {
                            self.status = "Die Datei ist kein bekannter Schlüssel.".into();
                        }
                    }
                }
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

                                        if self.method.key_based() && self.keygen {
                                            ui.label("Nutzerkennung (Name und optional E-Mail)");
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.user_id)
                                                    .hint_text("Anna Beispiel <anna@example.org>")
                                                    .desired_width(f32::INFINITY),
                                            );
                                        }

                                        if self.method.key_based() && !self.keygen {
                                            ui.add_space(12.0);
                                            if self.encrypting {
                                                ui.label(format!(
                                                    "Empfängerschlüssel ({})",
                                                    self.method.label()
                                                ));
                                                if !self.recipients.is_empty() {
                                                    let candidates: Vec<&RecipientKey> = self
                                                        .recipients
                                                        .iter()
                                                        .filter(|entry| entry.method == self.method)
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
                                                ui.label("Geheimer Schlüssel");
                                                ui.label(self.key.as_deref().map_or(
                                                    "Kein Schlüssel ausgewählt – im Menüband unter „Schlüssel“ öffnen"
                                                        .to_owned(),
                                                    |path| path.display().to_string(),
                                                ));
                                            }
                                        }

                                        if self.method.key_based() && self.text_mode && !self.keygen {
                                            ui.add_space(20.0);
                                            ui.label(if self.encrypting {
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
                                                ui.label(if self.encrypting {
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
                                            ui.add_space(6.0);
                                            egui::Frame::new()
                                                .fill(egui::Color32::from_rgb(239, 242, 245))
                                                .corner_radius(egui::CornerRadius::same(9))
                                                .inner_margin(egui::Margin::symmetric(12, 12))
                                                .show(ui, |ui| {
                                                    ui.set_width(ui.available_width());
                                                    ui.label(self.input.as_deref().map_or_else(
                                                        || {
                                                            "Wähle eine Datei oder einen Ordner …"
                                                                .to_owned()
                                                        },
                                                        |path| path.display().to_string(),
                                                    ));
                                                });
                                        }

                                        ui.add_space(18.0);
                                        if !self.method.key_based() || !self.encrypting || self.keygen {
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
                                                    } else {
                                                        "Passwort eingeben"
                                                    })
                                                    .desired_width(f32::INFINITY),
                                            );
                                            if (!self.method.key_based() && self.encrypting)
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
                                            let action = if self.method.key_based() && self.keygen {
                                                "Schlüsselpaar erstellen"
                                            } else if self.encrypting {
                                                "Jetzt verschlüsseln"
                                            } else {
                                                "Jetzt entschlüsseln"
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
                                Method::Pgp => "OpenPGP · Ed25519 · X25519 · AES-256/OCB",
                                Method::Pqc => "PQC · ML-KEM-768 · HKDF-SHA256 · XChaCha20-Poly1305",
                            })
                            .size(11.0)
                            .color(egui::Color32::from_rgb(104, 116, 130)),
                        );
                    });
                });
            });

        if self.show_about {
            let mut close = false;
            egui::Window::new("Über cryptool")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ui.ctx(), |ui| {
                    ui.set_max_width(340.0);
                    ui.label(egui::RichText::new("cryptool 0.2.0").strong());
                    ui.label("Lokale Ver- und Entschlüsselung von Dateien und Text.");
                    ui.add_space(8.0);
                    ui.label("CTX · Argon2id · XChaCha20-Poly1305");
                    ui.label("OpenPGP · Ed25519 · X25519 · AES-256/OCB");
                    ui.label("PQC · ML-KEM-768 · HKDF-SHA256 · XChaCha20-Poly1305");
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
    Shield,
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
    if bytes.starts_with(b"-----BEGIN CRYPTOOL PQC ")
        || bytes.starts_with(b"CTPK")
        || bytes.starts_with(b"CTSK")
    {
        Some(Method::Pqc)
    } else if bytes.starts_with(b"-----BEGIN PGP ")
        || bytes.first().is_some_and(|byte| byte & 0x80 != 0)
    {
        Some(Method::Pgp)
    } else {
        None
    }
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
        let (method, label, file_name) = match parts.as_slice() {
            [tag, label, file_name] => {
                let Some(method) = method_from_tag(tag) else {
                    continue;
                };
                (Some(method), *label, *file_name)
            }
            // Altes Format ohne Verfahren: anhand des Schlüsseldatei-Inhalts
            // zuordnen; alte Einträge waren in der Regel OpenPGP.
            [label, file_name] => (None, *label, *file_name),
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
        recipients.push(RecipientKey {
            label: label.to_owned(),
            path,
            method,
        });
    }
    recipients
}

fn run_operation(
    input: PathBuf,
    output: PathBuf,
    key: Option<PathBuf>,
    password: SecretString,
    encrypting: bool,
    method: Method,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    let mut on_progress = |progress| {
        let _ = events.send(Event::Progress(progress));
    };
    let result = match method {
        Method::Ctx => {
            if encrypting {
                encrypt_path(&input, &output, password, false, &mut on_progress, &cancel)
                    .map(|_| ())
            } else {
                decrypt_path(&input, &output, password, false, &mut on_progress, &cancel)
            }
        }
        Method::Pgp => {
            let key = key.expect("OpenPGP-Operation benötigt einen Schlüssel");
            if encrypting {
                pgp_encrypt_path(
                    &input,
                    &output,
                    &key,
                    false,
                    false,
                    &mut on_progress,
                    &cancel,
                )
                .map(|_| ())
            } else {
                pgp_decrypt_path(
                    &input,
                    &output,
                    &key,
                    password,
                    false,
                    &mut on_progress,
                    &cancel,
                )
            }
        }
        Method::Pqc => {
            let key = key.expect("PQC-Operation benötigt einen Schlüssel");
            if encrypting {
                pqc_encrypt_path(&input, &output, &key, false, &mut on_progress, &cancel)
                    .map(|_| ())
            } else {
                pqc_decrypt_path(
                    &input,
                    &output,
                    &key,
                    password,
                    false,
                    &mut on_progress,
                    &cancel,
                )
            }
        }
    };
    let message = result
        .map(|()| format!("Fertig: {}", output.display()))
        .map_err(|error| error.to_string());
    let _ = events.send(Event::Finished(message));
}

fn default_output(input: &std::path::Path, encrypting: bool, method: Method) -> PathBuf {
    if encrypting {
        let mut name = input.as_os_str().to_owned();
        name.push(format!(".{}", method.extension()));
        PathBuf::from(name)
    } else {
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

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([830.0, 850.0])
            .with_resizable(false)
            .with_maximize_button(false)
            .with_maximized(false)
            .with_fullscreen(false),
        ..Default::default()
    };
    eframe::run_native(
        "cryptool",
        options,
        Box::new(|_creation_context| Ok(Box::<CryptoolApp>::default())),
    )
}
