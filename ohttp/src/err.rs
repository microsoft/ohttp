use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "rust-hpke")]
    #[error("a problem occurred with the AEAD")]
    Aead(#[from] aead::Error),
    #[error("AEAD mode mismatch")]
    AeadMode,
    #[cfg(feature = "nss")]
    #[error("a problem occurred during cryptographic processing: {0}")]
    Crypto(#[from] crate::nss::Error),
    #[error("an error was found in the format")]
    Format,
    #[cfg(all(feature = "rust-hpke", not(feature = "pq")))]
    #[error("a problem occurred with HPKE: {0}")]
    Hpke(#[from] ::hpke::HpkeError),
    #[cfg(all(feature = "rust-hpke", feature = "pq"))]
    #[error("a problem occurred with HPKE: {0}")]
    Hpke(#[from] ::hpke_pq::HpkeError),
    #[error("an internal error occurred")]
    Internal,
    #[error("the wrong type of key was provided for the selected KEM")]
    InvalidKeyType,
    #[error("the wrong KEM was specified")]
    InvalidKem,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the key ID was invalid")]
    KeyId,
    #[error("Returned a different key ID from the one requested : {0} {1}")]
    KeyIdMismatch(u8, u8),
    #[error("Symmetric key is empty")]
    SymmetricKeyEmpty,
    #[error("the configuration contained too many symmetric suites")]
    TooManySymmetricSuites,
    #[error("a field was truncated")]
    Truncated,
    #[error("the two lengths are not equal : {0} {1}")]
    UnequalLength(usize, usize),
    #[error("the configuration was not supported")]
    Unsupported,
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_v: std::num::TryFromIntError) -> Self {
        Self::TooManySymmetricSuites
    }
}

pub type Res<T> = Result<T, Error>;
