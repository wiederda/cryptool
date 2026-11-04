//! Gemeinsame öffentliche API für CLI und GUI.
//!
//! Dieses Crate orchestriert Dateioperationen, CTX-Container und den OpenPGP-Modus.
//! Kryptografische Grundbausteine liegen in `cryptool-core`.

mod engine;
mod pgp;
mod pqc;

pub use cryptool_core::{ExposeSecret, SecretString};
pub use engine::{
    decrypt_path, encrypt_path, read_header, Error, Header, Progress, Report, Result, VerifyReport,
    DEFAULT_CHUNK_SIZE, EXTENSION, HEADER_LEN,
};
pub use pgp::{
    decrypt_path as pgp_decrypt_path, decrypt_text as pgp_decrypt_text,
    encrypt_path as pgp_encrypt_path, encrypt_text as pgp_encrypt_text,
    generate_key as pgp_generate_key, sign_path as pgp_sign_path, verify_path as pgp_verify_path,
    ARMOR_EXTENSION as PGP_ARMOR_EXTENSION, EXTENSION as PGP_EXTENSION,
    SIGNATURE_ARMOR_EXTENSION as PGP_SIGNATURE_ARMOR_EXTENSION,
    SIGNATURE_EXTENSION as PGP_SIGNATURE_EXTENSION,
};
pub use pqc::{
    decrypt_path as pqc_decrypt_path, decrypt_text as pqc_decrypt_text,
    encrypt_path as pqc_encrypt_path, encrypt_text as pqc_encrypt_text,
    generate_key as pqc_generate_key, sign_path as pqc_sign_path, verify_path as pqc_verify_path,
    PublicKey as PqcPublicKey, EXTENSION as PQC_EXTENSION,
    PUBLIC_KEY_EXTENSION as PQC_PUBLIC_KEY_EXTENSION,
    SECRET_KEY_EXTENSION as PQC_SECRET_KEY_EXTENSION,
    SIGNATURE_ARMOR_EXTENSION as PQC_SIGNATURE_ARMOR_EXTENSION,
    SIGNATURE_EXTENSION as PQC_SIGNATURE_EXTENSION, TEXT_EXTENSION as PQC_TEXT_EXTENSION,
};
