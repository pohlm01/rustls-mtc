use pki_types::CertificateDer;
use crate::crypto::signer::X509OrBikeshedCertChain;

use crate::sign;

/// ActiveCertifiedKey wraps [`sign::X509CertifiedKey`] and tracks OSCP state in a single handshake.
pub(super) struct ActiveCertifiedKey<'a> {
    key: &'a sign::CertifiedKey,
    ocsp: Option<&'a [u8]>,
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(key: &sign::CertifiedKey) -> ActiveCertifiedKey {
        ActiveCertifiedKey {
            key,
            ocsp: match key {
                sign::CertifiedKey::X509(x509) => x509.ocsp.as_deref(),
                _ => None
            }
        }
    }

    /// Get the certificate chain
    #[inline]
    pub(super) fn get_cert(&self) -> X509OrBikeshedCertChain {
        self.key.cert()
    }

    /// Get the signing key
    #[inline]
    pub(super) fn get_key(&self) -> &dyn sign::SigningKey {
        self.key.key()
    }

    #[inline]
    pub(super) fn get_ocsp(&self) -> Option<&[u8]> {
        self.ocsp
    }
}
