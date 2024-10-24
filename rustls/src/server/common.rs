use pki_types::CertificateDer;

use crate::msgs::handshake::BikeshedCertificate;
use crate::{sign, CertificateType};

/// ActiveCertifiedKey wraps [`sign::CertifiedKey`] and tracks OSCP state in a single handshake.
pub(super) struct ActiveCertifiedKey<'a> {
    key: &'a sign::CertifiedKey,
    ocsp: Option<&'a [u8]>,
}

pub(super) enum Certificate<'a> {
    X509(&'a [CertificateDer<'static>]),
    Bikeshed(&'a BikeshedCertificate),
}

impl<'a> Certificate<'a> {
    pub(crate) fn into_x509(self) -> Option<&'a [CertificateDer<'static>]> {
        match self {
            Certificate::X509(chain) => Some(chain),
            Certificate::Bikeshed(_) => None,
        }
    }

    pub(crate) fn certificate_type(&self) -> CertificateType {
        match self {
            Certificate::X509(_) => CertificateType::X509,
            Certificate::Bikeshed(_) => CertificateType::Bikeshed,
        }
    }
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(key: &sign::CertifiedKey) -> ActiveCertifiedKey<'_> {
        ActiveCertifiedKey {
            key,
            ocsp: key.ocsp(),
        }
    }

    /// Get the certificate chain
    #[inline]
    pub(super) fn get_cert(&self) -> Certificate<'a> {
        match self.key {
            sign::CertifiedKey::X509 { cert, .. } => Certificate::X509(cert),
            sign::CertifiedKey::Bikeshed { cert, .. } => Certificate::Bikeshed(cert),
        }
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
