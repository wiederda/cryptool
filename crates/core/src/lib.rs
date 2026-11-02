//! Kryptografische Bausteine. Dateiformate und Dateioperationen gehören in `cryptool-lib`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::{Zeroize, Zeroizing};

pub use secrecy::{ExposeSecret, SecretString};

pub type Cipher = XChaCha20Poly1305;

/// Leitet einen 256-Bit-Schlüssel mit Argon2id ab. Der übergebene Passwortpuffer
/// wird nach der Ableitung gelöscht; der Schlüssel wird beim Drop ebenfalls gelöscht.
pub fn derive_key(
    password: &str,
    salt: &[u8; 16],
    m_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> std::result::Result<Zeroizing<[u8; 32]>, String> {
    let params =
        Params::new(m_kib, iterations, parallelism, Some(32)).map_err(|error| error.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| error.to_string())?;
    Ok(key)
}

/// Erzeugt den AEAD-Chiffre-Kontext aus einem abgeleiteten Schlüssel.
pub fn xchacha20poly1305(key: &[u8; 32]) -> Cipher {
    Cipher::new(GenericArray::from_slice(key))
}

/// Löscht einen temporären Passwortpuffer zuverlässig.
pub fn clear_password(password: &mut String) {
    password.zeroize();
}
