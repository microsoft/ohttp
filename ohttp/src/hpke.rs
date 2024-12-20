macro_rules! convert_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<u16> for $name {
            type Error = crate::Error;

            fn try_from(v: u16) -> Result<Self, Self::Error> {
                match v {
                    $($(#[$vmeta])*
                      x if x == $name::$vname as u16
                      => Ok($name::$vname),)*
                    _ => Err(crate::Error::Unsupported),
                }
            }
        }

        impl std::convert::From<$name> for u16 {
            fn from(v: $name) -> u16 {
                v as u16
            }
        }
    }
}

convert_enum! {
pub enum Kem {
    P384Sha384 = 17,

    X25519Sha256 = 32,

    #[cfg(feature = "pq")]
    X25519Kyber768Draft00 = 48,
}
}

impl Kem {
    #[must_use]
    pub fn n_enc(self) -> usize {
        match self {
            Kem::P384Sha384 => 97,

            Kem::X25519Sha256 => 32,

            #[cfg(feature = "pq")]
            Kem::X25519Kyber768Draft00 => 1120,
        }
    }

    #[must_use]
    pub fn n_pk(self) -> usize {
        match self {
            Kem::P384Sha384 => 97,

            Kem::X25519Sha256 => 32,

            #[cfg(feature = "pq")]
            Kem::X25519Kyber768Draft00 => 1216,
        }
    }
}

convert_enum! {
    pub enum Kdf {
        HkdfSha256 = 1,
        HkdfSha384 = 2,
        HkdfSha512 = 3,
    }
}

convert_enum! {
    pub enum Aead {
        Aes128Gcm = 1,
        Aes256Gcm = 2,
        ChaCha20Poly1305 = 3,
    }
}

impl Aead {
    /// The size of the key for this AEAD.
    #[must_use]
    pub fn n_k(self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
        }
    }

    /// The size of the nonce for this AEAD.
    #[must_use]
    pub fn n_n(self) -> usize {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 12,
        }
    }

    /// The size of the tag for this AEAD.
    #[must_use]
    #[allow(clippy::unused_self)] // This is only presently constant.
    pub fn n_t(self) -> usize {
        16
    }
}
