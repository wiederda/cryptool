use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use cryptool_lib as ct;
use ct::{Progress, SecretString};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "cryptool",
    version,
    about = "Dateien und Ordner verschlüsseln und entschlüsseln"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Datei oder Ordner mit Passwort verschlüsseln
    Encrypt(CryptArgs),
    /// Datei oder Ordner mit Passwort entschlüsseln
    Decrypt(CryptArgs),
    /// Header einer verschlüsselten Datei anzeigen (ohne Passwort)
    Inspect { file: PathBuf },
    /// OpenPGP (RFC 9580): Schlüssel erzeugen und Nachrichten ver-/entschlüsseln
    Pgp {
        #[command(subcommand)]
        cmd: PgpCmd,
    },
    /// PQC (ML-KEM-768): Schlüssel erzeugen und Nachrichten ver-/entschlüsseln
    Pqc {
        #[command(subcommand)]
        cmd: PqcCmd,
    },
}

#[derive(Subcommand)]
enum PgpCmd {
    /// Schlüsselfpaar erzeugen (Ed25519 + X25519-Unterschlüssel)
    Keygen(PgpKeygenArgs),
    /// Datei oder Ordner für einen Empfänger verschlüsseln
    Encrypt(PgpEncryptArgs),
    /// PGP-Nachricht mit dem geheimen Schlüssel entschlüsseln
    Decrypt(PgpDecryptArgs),
    /// Einzelne Datei abgetrennt signieren
    Sign(PgpSignArgs),
    /// Abgetrennte PGP-Signatur prüfen
    Verify(PgpVerifyArgs),
}

#[derive(Subcommand)]
enum PqcCmd {
    /// ML-KEM-768/ML-DSA-65-Schlüsselpaar erzeugen
    Keygen(PqcKeygenArgs),
    /// Datei oder Ordner für einen Empfänger verschlüsseln
    Encrypt(PqcEncryptArgs),
    /// PQC-Nachricht mit dem geheimen Schlüssel entschlüsseln
    Decrypt(PqcDecryptArgs),
    /// Einzelne Datei abgetrennt signieren
    Sign(PqcSignArgs),
    /// Abgetrennte PQC-Signatur prüfen
    Verify(PqcVerifyArgs),
}

/// Gemeinsame Passwort-Argumente (lesbar für Skripte und interaktiv).
#[derive(Args)]
struct PasswordArgs {
    /// Passwort aus der ersten Zeile von stdin lesen (für Skripte)
    #[arg(long, conflicts_with = "password_file")]
    password_stdin: bool,
    /// Passwort aus der ersten Zeile dieser Datei lesen (für Skripte)
    #[arg(long, value_name = "DATEI")]
    password_file: Option<PathBuf>,
    /// Beim interaktiven Verschlüsseln das Passwort nicht wiederholen lassen
    #[arg(long)]
    no_confirm: bool,
}

impl PasswordArgs {
    /// Liest das Passwort; bei `confirm` wird interaktiv zweimal gefragt.
    fn read(&self, confirm: bool) -> ct::Result<SecretString> {
        let interactive = io::stdin().is_terminal();

        let mut pw = if self.password_stdin {
            read_secret_line(&mut io::stdin().lock())?
        } else if let Some(path) = &self.password_file {
            read_secret_line(&mut BufReader::new(File::open(path)?))?
        } else if !interactive {
            return Err(ct::Error::Invalid(
                "Kein Terminal: Passwort bitte mit --password-stdin oder --password-file übergeben"
                    .into(),
            ));
        } else {
            let mut p1 = rpassword::prompt_password("Passwort: ")?;
            if confirm {
                let mut p2 = rpassword::prompt_password("Passwort wiederholen: ")?;
                let same = p1 == p2;
                p2.zeroize();
                if !same {
                    p1.zeroize();
                    return Err(ct::Error::Invalid(
                        "Passwörter stimmen nicht überein".into(),
                    ));
                }
            }
            p1
        };

        if pw.is_empty() {
            pw.zeroize();
            return Err(ct::Error::Invalid(
                "Leeres Passwort ist nicht erlaubt".into(),
            ));
        }
        Ok(SecretString::new(pw))
    }
}

#[derive(Args)]
struct PgpKeygenArgs {
    /// Kennung für den Schlüssel, z. B. "Anna Beispiel <anna@example.com>"
    user_id: String,
    /// Datei für den geheimen Schlüssel (Standard: schluessel.sec.asc)
    #[arg(short, long, value_name = "DATEI")]
    secret: Option<PathBuf>,
    /// Datei für den öffentlichen Schlüssel (Standard: schluessel.pub.asc)
    #[arg(short = 'P', long, value_name = "DATEI")]
    public: Option<PathBuf>,
    #[command(flatten)]
    password: PasswordArgs,
    /// Vorhandene Schlüsseldateien überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PgpEncryptArgs {
    /// Eingabe: Datei oder Ordner
    input: PathBuf,
    /// Ziel (Standard: <eingabe>.pgp bzw. <eingabe>.asc)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Öffentlicher Schlüssel des Empfängers (.pub.asc oder binär)
    #[arg(short = 'r', long, value_name = "DATEI")]
    recipient: PathBuf,
    /// Ausgabe als ASCII-Armor (.asc) statt binär (.pgp)
    #[arg(long)]
    armor: bool,
    /// Vorhandene Ausgabedatei überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PgpDecryptArgs {
    /// Eingabe: die .pgp- bzw. .asc-Datei
    input: PathBuf,
    /// Ziel (Standard: ohne Endung; bei Ordner-Archiven der Ordnername)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Eigener geheimer Schlüssel (.sec.asc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    #[command(flatten)]
    password: PasswordArgs,
    /// Vorhandene Ausgabedatei überschreiben (Ordner werden nie überschrieben)
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PgpSignArgs {
    /// Eingabe: die zu signierende Datei (kein Ordner)
    input: PathBuf,
    /// Signaturdatei (Standard: <eingabe>.sig bzw. <eingabe>.sig.asc)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Eigener geheimer Schlüssel (.sec.asc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    #[command(flatten)]
    password: PasswordArgs,
    /// Signatur als ASCII-Armor (.sig.asc) statt binär (.sig)
    #[arg(long)]
    armor: bool,
    /// Vorhandene Signaturdatei überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PgpVerifyArgs {
    /// Eingabe: die zu prüfende Datei
    input: PathBuf,
    /// Signaturdatei (Standard: <eingabe>.sig oder <eingabe>.sig.asc)
    #[arg(short = 's', long, value_name = "DATEI")]
    signature: Option<PathBuf>,
    /// Öffentlicher Schlüssel des Unterzeichners (.pub.asc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PqcKeygenArgs {
    /// Kennung für den Schlüssel, z. B. "Anna Beispiel <anna@example.com>"
    user_id: String,
    /// Datei für den geheimen Schlüssel (Standard: schluessel.sec.pqc)
    #[arg(short, long, value_name = "DATEI")]
    secret: Option<PathBuf>,
    /// Datei für den öffentlichen Schlüssel (Standard: schluessel.pub.pqc)
    #[arg(short = 'P', long, value_name = "DATEI")]
    public: Option<PathBuf>,
    #[command(flatten)]
    password: PasswordArgs,
    /// Vorhandene Schlüsseldateien überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PqcEncryptArgs {
    /// Eingabe: Datei oder Ordner
    input: PathBuf,
    /// Ziel (Standard: <eingabe>.pqc)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Öffentlicher ML-KEM-Schlüssel des Empfängers (.pub.pqc oder binär)
    #[arg(short = 'r', long, value_name = "DATEI")]
    recipient: PathBuf,
    /// Vorhandene Ausgabedatei überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PqcDecryptArgs {
    /// Eingabe: die .pqc-Datei
    input: PathBuf,
    /// Ziel (Standard: ohne .pqc; bei Ordner-Nachrichten der Ordnername)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Eigener geheimer Schlüssel (.sec.pqc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    #[command(flatten)]
    password: PasswordArgs,
    /// Vorhandene Ausgabedatei überschreiben (Ordner werden nie überschrieben)
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PqcSignArgs {
    /// Eingabe: die zu signierende Datei (kein Ordner)
    input: PathBuf,
    /// Signaturdatei (Standard: <eingabe>.pqc.sig bzw. <eingabe>.pqc.sig.asc)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Eigener geheimer Schlüssel (.sec.pqc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    #[command(flatten)]
    password: PasswordArgs,
    /// Signatur als ASCII-Armor (.pqc.sig.asc) statt binär (.pqc.sig)
    #[arg(long)]
    armor: bool,
    /// Vorhandene Signaturdatei überschreiben
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PqcVerifyArgs {
    /// Eingabe: die zu prüfende Datei
    input: PathBuf,
    /// Signaturdatei (Standard: <eingabe>.pqc.sig oder <eingabe>.pqc.sig.asc)
    #[arg(short = 's', long, value_name = "DATEI")]
    signature: Option<PathBuf>,
    /// Öffentlicher Schlüssel des Unterzeichners (.pub.pqc oder binär)
    #[arg(short = 'k', long, value_name = "DATEI")]
    key: PathBuf,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct CryptArgs {
    /// Eingabe: Datei oder Ordner (beim Entschlüsseln: die .ctx-Datei)
    input: PathBuf,
    /// Ziel (Standard: <eingabe>.ctx bzw. ohne .ctx)
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(flatten)]
    password: PasswordArgs,
    /// Vorhandene Ausgabedatei überschreiben (Ordner werden nie überschrieben)
    #[arg(short, long)]
    force: bool,
    /// Keine Fortschrittsanzeige und keine Hinweise
    #[arg(short, long)]
    quiet: bool,
}

// Exit-Codes
const EXIT_ERROR: u8 = 1;
const EXIT_SIGNATURE_INVALID: u8 = 2;
const EXIT_WRONG_PASSWORD: u8 = 3;
const EXIT_CANCELED: u8 = 130;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Fehler: {e}");
            ExitCode::from(match e {
                ct::Error::SignatureInvalid => EXIT_SIGNATURE_INVALID,
                ct::Error::WrongPasswordOrCorrupt => EXIT_WRONG_PASSWORD,
                ct::Error::Canceled => EXIT_CANCELED,
                _ => EXIT_ERROR,
            })
        }
    }
}

fn run(cmd: Cmd) -> ct::Result<()> {
    match cmd {
        Cmd::Encrypt(a) => crypt(a, true),
        Cmd::Decrypt(a) => crypt(a, false),
        Cmd::Pgp { cmd } => pgp_run(cmd),
        Cmd::Pqc { cmd } => pqc_run(cmd),
        Cmd::Inspect { file } => {
            let h = ct::read_header(&file)?;
            println!("Format-Version : {}", h.version);
            println!(
                "Inhalt         : {}",
                if h.is_dir() {
                    "Ordner (tar + zstd)"
                } else {
                    "einzelne Datei"
                }
            );
            println!(
                "Cipher         : XChaCha20-Poly1305 (STREAM, Chunk {} Byte)",
                h.chunk_size
            );
            println!(
                "KDF            : Argon2id (m = {} MiB, t = {}, p = {})",
                h.m_kib / 1024,
                h.t,
                h.p
            );
            Ok(())
        }
    }
}

fn crypt(a: CryptArgs, encrypting: bool) -> ct::Result<()> {
    let output = a
        .output
        .clone()
        .unwrap_or_else(|| default_output(&a.input, encrypting));

    let password = a.password.read(encrypting && !a.password.no_confirm)?;

    // Strg+C setzt nur ein Flag; die Bibliothek räumt Teildateien auf.
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let c = Arc::clone(&cancel);
        let _ = ctrlc::set_handler(move || c.store(true, Ordering::Relaxed));
    }

    let show = !a.quiet && io::stderr().is_terminal();
    let mut last = u64::MAX;
    let mut on_progress = |p: Progress| {
        if !show {
            return;
        }
        let pct = if p.total == 0 {
            100
        } else {
            p.done
                .checked_mul(100)
                .map_or(100, |v| (v / p.total).min(100))
        };
        if pct != last {
            last = pct;
            eprint!("\r{pct:3} %");
        }
    };

    let res = if encrypting {
        ct::encrypt_path(
            &a.input,
            &output,
            password,
            a.force,
            &mut on_progress,
            &cancel,
        )
    } else {
        ct::decrypt_path(
            &a.input,
            &output,
            password,
            a.force,
            &mut on_progress,
            &cancel,
        )
        .map(|()| ct::Report::default())
    };
    if show {
        eprintln!();
    }
    let report = res?;
    if !a.quiet {
        if report.skipped > 0 {
            eprintln!(
                "Hinweis: {} Symlink(s)/Sonderdatei(en) wurden nicht aufgenommen.",
                report.skipped
            );
        }
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn default_output(input: &Path, encrypting: bool) -> PathBuf {
    if encrypting {
        return default_output_ext(input, ct::EXTENSION);
    }
    if input.extension().is_some_and(|e| e == ct::EXTENSION) {
        input.with_extension("")
    } else {
        let mut s = input.as_os_str().to_owned();
        s.push(".dec");
        PathBuf::from(s)
    }
}

/// "<eingabe>" -> "<eingabe>.<ext>" (bei "." oder ".." den echten Namen auflösen).
fn default_output_ext(input: &Path, ext: &str) -> PathBuf {
    let p = if input.file_name().is_some() {
        input.to_path_buf()
    } else {
        std::fs::canonicalize(input).unwrap_or_else(|_| input.to_path_buf())
    };
    match p.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(format!(".{ext}"));
            p.with_file_name(s)
        }
        None => PathBuf::from(format!("cryptool.{ext}")),
    }
}

/// Entschlüsselte PGP-Nachricht: "brief.pgp" -> "brief"; Archiv-Namen wie
/// "ordner.tar.zst.pgp" -> Ordner "ordner".
fn pgp_default_output_decrypt(input: &Path) -> PathBuf {
    let mut name = match input.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_owned(),
        None => return PathBuf::from("ziel.dec"),
    };

    if (name.ends_with(".asc") || name.ends_with(".pgp")) && name.len() > 4 {
        name.truncate(name.len() - 4);
    } else {
        name.push_str(".dec");
    }
    // Archiv-Klartextnamen enden auf ".tar.zst": daraus wird der Zielordner.
    if name.len() > 8 && name.ends_with(".tar.zst") {
        name.truncate(name.len() - 8);
    }
    PathBuf::from(name)
}

fn pgp_run(cmd: PgpCmd) -> ct::Result<()> {
    // Strg+C setzt nur ein Flag; die Bibliothek räumt Teildateien auf.
    let cancel = setup_cancel();
    match cmd {
        PgpCmd::Keygen(a) => pgp_keygen(a),
        PgpCmd::Encrypt(a) => pgp_encrypt(a, &cancel),
        PgpCmd::Decrypt(a) => pgp_decrypt(a, &cancel),
        PgpCmd::Sign(a) => pgp_sign(a, &cancel),
        PgpCmd::Verify(a) => pgp_verify(a, &cancel),
    }
}

fn pgp_keygen(a: PgpKeygenArgs) -> ct::Result<()> {
    let secret_out = a
        .secret
        .clone()
        .unwrap_or_else(|| PathBuf::from("schluessel.sec.asc"));
    let public_out = a
        .public
        .clone()
        .unwrap_or_else(|| PathBuf::from("schluessel.pub.asc"));

    let passphrase = a.password.read(true)?;
    ct::pgp_generate_key(&a.user_id, passphrase, &secret_out, &public_out, a.force)?;
    if !a.quiet {
        eprintln!("Geheimer Schlüssel   : {}", secret_out.display());
        eprintln!("Öffentlicher Schlüssel: {}", public_out.display());
        eprintln!(
            "Hinweis: Nur {} weitergeben; {} sicher aufbewahren.",
            public_out.display(),
            secret_out.display()
        );
    }
    Ok(())
}

fn pgp_encrypt(a: PgpEncryptArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a.output.clone().unwrap_or_else(|| {
        default_output_ext(
            &a.input,
            if a.armor {
                ct::PGP_ARMOR_EXTENSION
            } else {
                ct::PGP_EXTENSION
            },
        )
    });

    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pgp_encrypt_path(
        &a.input,
        &output,
        &a.recipient,
        a.armor,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    let report = res?;
    if !a.quiet {
        if report.skipped > 0 {
            eprintln!(
                "Hinweis: {} Symlink(s)/Sonderdatei(en) wurden nicht aufgenommen.",
                report.skipped
            );
        }
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pgp_decrypt(a: PgpDecryptArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a
        .output
        .clone()
        .unwrap_or_else(|| pgp_default_output_decrypt(&a.input));

    let passphrase = a.password.read(false)?;
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pgp_decrypt_path(
        &a.input,
        &output,
        &a.key,
        passphrase,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    res?;
    if !a.quiet {
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pgp_sign(a: PgpSignArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a.output.clone().unwrap_or_else(|| {
        default_output_ext(
            &a.input,
            if a.armor {
                ct::PGP_SIGNATURE_ARMOR_EXTENSION
            } else {
                ct::PGP_SIGNATURE_EXTENSION
            },
        )
    });
    let passphrase = a.password.read(false)?;
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pgp_sign_path(
        &a.input,
        &output,
        &a.key,
        passphrase,
        a.armor,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    res?;
    if !a.quiet {
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pgp_verify(a: PgpVerifyArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let signature = a.signature.clone().unwrap_or_else(|| {
        default_signature_input(
            &a.input,
            ct::PGP_SIGNATURE_EXTENSION,
            ct::PGP_SIGNATURE_ARMOR_EXTENSION,
        )
    });
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pgp_verify_path(&a.input, &signature, &a.key, &mut on_progress, cancel);
    if show {
        eprintln!();
    }
    let report = res?;
    print_verify_report(&report, a.quiet);
    Ok(())
}

fn print_verify_report(report: &ct::VerifyReport, quiet: bool) {
    if quiet {
        return;
    }
    println!("Gültige Signatur");
    println!("Unterzeichner : {}", report.signer);
    println!("Schlüssel     : {}", report.key_id);
    match report.created {
        Some(secs) => println!("Zeitpunkt     : {secs} (Unix-Zeit)"),
        None => println!("Zeitpunkt     : nicht angegeben"),
    }
}

/// Sucht die Standard-Signaturdatei; bevorzugt die binäre Variante, fällt bei
/// Bedarf auf die ASCII-Variante zurück.
fn default_signature_input(input: &Path, binary_ext: &str, armor_ext: &str) -> PathBuf {
    let binary = default_output_ext(input, binary_ext);
    if binary.exists() {
        return binary;
    }
    let armored = default_output_ext(input, armor_ext);
    if armored.exists() {
        armored
    } else {
        binary
    }
}

/// Entschlüsselte PQC-Nachricht: "brief.pqc" -> "brief".
fn pqc_default_output_decrypt(input: &Path) -> PathBuf {
    let mut name = match input.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_owned(),
        None => return PathBuf::from("ziel.dec"),
    };

    if name.ends_with(".pqc") && name.len() > 4 {
        name.truncate(name.len() - 4);
    } else {
        name.push_str(".dec");
    }
    PathBuf::from(name)
}

fn pqc_run(cmd: PqcCmd) -> ct::Result<()> {
    // Strg+C setzt nur ein Flag; die Bibliothek räumt Teildateien auf.
    let cancel = setup_cancel();
    match cmd {
        PqcCmd::Keygen(a) => pqc_keygen(a),
        PqcCmd::Encrypt(a) => pqc_encrypt(a, &cancel),
        PqcCmd::Decrypt(a) => pqc_decrypt(a, &cancel),
        PqcCmd::Sign(a) => pqc_sign(a, &cancel),
        PqcCmd::Verify(a) => pqc_verify(a, &cancel),
    }
}

fn pqc_keygen(a: PqcKeygenArgs) -> ct::Result<()> {
    let secret_out = a
        .secret
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("schluessel.{}", ct::PQC_SECRET_KEY_EXTENSION)));
    let public_out = a
        .public
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("schluessel.{}", ct::PQC_PUBLIC_KEY_EXTENSION)));

    let passphrase = a.password.read(true)?;
    ct::pqc_generate_key(&a.user_id, passphrase, &secret_out, &public_out, a.force)?;
    if !a.quiet {
        eprintln!("Geheimer Schlüssel   : {}", secret_out.display());
        eprintln!("Öffentlicher Schlüssel: {}", public_out.display());
        eprintln!(
            "Hinweis: Nur {} weitergeben; {} sicher aufbewahren.",
            public_out.display(),
            secret_out.display()
        );
    }
    Ok(())
}

fn pqc_encrypt(a: PqcEncryptArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a
        .output
        .clone()
        .unwrap_or_else(|| default_output_ext(&a.input, ct::PQC_EXTENSION));

    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pqc_encrypt_path(
        &a.input,
        &output,
        &a.recipient,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    let report = res?;
    if !a.quiet {
        if report.skipped > 0 {
            eprintln!(
                "Hinweis: {} Symlink(s)/Sonderdatei(en) wurden nicht aufgenommen.",
                report.skipped
            );
        }
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pqc_decrypt(a: PqcDecryptArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a
        .output
        .clone()
        .unwrap_or_else(|| pqc_default_output_decrypt(&a.input));

    let passphrase = a.password.read(false)?;
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pqc_decrypt_path(
        &a.input,
        &output,
        &a.key,
        passphrase,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    res?;
    if !a.quiet {
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pqc_sign(a: PqcSignArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let output = a.output.clone().unwrap_or_else(|| {
        default_output_ext(
            &a.input,
            if a.armor {
                ct::PQC_SIGNATURE_ARMOR_EXTENSION
            } else {
                ct::PQC_SIGNATURE_EXTENSION
            },
        )
    });
    let passphrase = a.password.read(false)?;
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pqc_sign_path(
        &a.input,
        &output,
        &a.key,
        passphrase,
        a.armor,
        a.force,
        &mut on_progress,
        cancel,
    );
    if show {
        eprintln!();
    }
    res?;
    if !a.quiet {
        eprintln!("-> {}", output.display());
    }
    Ok(())
}

fn pqc_verify(a: PqcVerifyArgs, cancel: &AtomicBool) -> ct::Result<()> {
    let signature = a.signature.clone().unwrap_or_else(|| {
        default_signature_input(
            &a.input,
            ct::PQC_SIGNATURE_EXTENSION,
            ct::PQC_SIGNATURE_ARMOR_EXTENSION,
        )
    });
    let show = !a.quiet && io::stderr().is_terminal();
    let mut on_progress = progress_cb(show);
    let res = ct::pqc_verify_path(&a.input, &signature, &a.key, &mut on_progress, cancel);
    if show {
        eprintln!();
    }
    let report = res?;
    print_verify_report(&report, a.quiet);
    Ok(())
}

/// Strg+C-Handler, der nur das Abbruch-Flag setzt.
fn setup_cancel() -> Arc<AtomicBool> {    let cancel = Arc::new(AtomicBool::new(false));
    {
        let c = Arc::clone(&cancel);
        let _ = ctrlc::set_handler(move || c.store(true, Ordering::Relaxed));
    }
    cancel
}

/// Fortschrittsanzeige auf stderr; ohne bekanntes Gesamtziel keine Anzeige.
fn progress_cb(show: bool) -> impl FnMut(Progress) {
    let mut last = u64::MAX;
    move |p: Progress| {
        if !show || p.total == 0 {
            return;
        }
        let pct = p
            .done
            .checked_mul(100)
            .map_or(100, |v| (v / p.total).min(100));
        if pct != last {
            last = pct;
            eprint!("\r{pct:3} %");
        }
    }
}

/// Liest eine Zeile ohne Zeilenende; der Rohpuffer wird gelöscht.
fn read_secret_line(r: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let secret = line.trim_end_matches(['\r', '\n']).to_owned();
    line.zeroize();
    Ok(secret)
}
