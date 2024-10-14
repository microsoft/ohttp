use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "rust-hpke")]
    #[error("a problem occurred with the AEAD")]
    Aead(#[from] aead::Error),
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
    #[error("Incorrect CBOR encoding in returned private key")]
    KMSCBOREncoding,
    #[error("Bad CBOR key type, expected P-384(2)")]
    KMSCBORKeyType,
    #[error("Unexpected field in exported private key from KMS")]
    KMSField,
    #[error("the key ID was invalid")]
    KMSKeyId,
    #[error("Missing private exponent in key returned from KMS")]
    KMSPrivateExponent,
    #[error("Invalid private key")]
    KMSPrivateKey,
    #[error("Max retries reached, giving up. Cannot reach key management service")]
    KMSUnreachable,
    #[error("an internal error occurred")]
    Internal,
    #[error("the wrong type of key was provided for the selected KEM")]
    InvalidKeyType,
    #[error("the wrong KEM was specified")]
    InvalidKem,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the key ID was invalid")]
    KeyId,
    #[error("Failed to get MAA token. You must be root to access TPM")]
    MAAToken,
    #[error("a field was truncated")]
    Truncated,
    #[error("the configuration was not supported")]
    Unsupported,
    #[error("the configuration contained too many symmetric suites")]
    TooManySymmetricSuites,
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_v: std::num::TryFromIntError) -> Self {
        Self::TooManySymmetricSuites
    }
}

pub type Res<T> = Result<T, Error>;
