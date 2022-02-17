use thiserror::Error;

#[derive(Error, Debug)]
/// An error thrown when interacting with the eth-keystore crate.
pub enum KeystoreError {
    /// An error thrown while decrypting an encrypted JSON keystore if the calculated MAC does not
    /// match the MAC declared in the keystore.
    #[error("Mac Mismatch")]
    MacMismatch,
    /// Invalid scrypt output length
    #[error("scrypt {0:?}")]
    ScryptInvalidParams(scrypt::errors::InvalidParams),
    /// Invalid scrypt output length
    #[error("scrypt {0:?}")]
    ScryptInvalidOuputLen(scrypt::errors::InvalidOutputLen),
    /// Invalid aes key nonce length
    #[error("aes {0:?}")]
    AesInvalidKeyNonceLength(aes::cipher::errors::InvalidLength),
}

impl From<scrypt::errors::InvalidParams> for KeystoreError {
    fn from(e: scrypt::errors::InvalidParams) -> Self {
        Self::ScryptInvalidParams(e)
    }
}

impl From<scrypt::errors::InvalidOutputLen> for KeystoreError {
    fn from(e: scrypt::errors::InvalidOutputLen) -> Self {
        Self::ScryptInvalidOuputLen(e)
    }
}

impl From<aes::cipher::errors::InvalidLength> for KeystoreError {
    fn from(e: aes::cipher::errors::InvalidLength) -> Self {
        Self::AesInvalidKeyNonceLength(e)
    }
}
