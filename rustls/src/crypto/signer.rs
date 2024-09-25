use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::CertificateDer;

use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::msgs::handshake::BikeshedCertificate;

/// An abstract signing key.
///
/// This interface is used by rustls to use a private signing key
/// for authentication.  This includes server and client authentication.
///
/// Objects of this type are always used within Rustls as
/// `Arc<dyn SigningKey>`. There are no concrete public structs in Rustls
/// that implement this trait.
///
/// There are two main ways to get a signing key:
///
///  - [`KeyProvider::load_private_key()`], or
///  - some other method outside of the `KeyProvider` extension trait,
///    for instance:
///    - [`crypto::ring::sign::any_ecdsa_type()`]
///    - [`crypto::ring::sign::any_eddsa_type()`]
///    - [`crypto::ring::sign::any_supported_type()`]
///    - [`crypto::aws_lc_rs::sign::any_ecdsa_type()`]
///    - [`crypto::aws_lc_rs::sign::any_eddsa_type()`]
///    - [`crypto::aws_lc_rs::sign::any_supported_type()`]
///
/// The `KeyProvider` method `load_private_key()` is called under the hood by
/// [`ConfigBuilder::with_single_cert()`],
/// [`ConfigBuilder::with_client_auth_cert()`], and
/// [`ConfigBuilder::with_single_cert_with_ocsp()`].
///
/// A signing key created outside of the `KeyProvider` extension trait can be used
/// to create a [`X509CertifiedKey`], which in turn can be used to create a
/// [`ResolvesServerCertUsingSni`]. Alternately, a `CertifiedKey` can be returned from a
/// custom implementation of the [`ResolvesServerCert`] or [`ResolvesClientCert`] traits.
///
/// [`KeyProvider::load_private_key()`]: crate::crypto::KeyProvider::load_private_key
/// [`ConfigBuilder::with_single_cert()`]: crate::ConfigBuilder::with_single_cert
/// [`ConfigBuilder::with_single_cert_with_ocsp()`]: crate::ConfigBuilder::with_single_cert_with_ocsp
/// [`ConfigBuilder::with_client_auth_cert()`]: crate::ConfigBuilder::with_client_auth_cert
/// [`crypto::ring::sign::any_ecdsa_type()`]: crate::crypto::ring::sign::any_ecdsa_type
/// [`crypto::ring::sign::any_eddsa_type()`]: crate::crypto::ring::sign::any_eddsa_type
/// [`crypto::ring::sign::any_supported_type()`]: crate::crypto::ring::sign::any_supported_type
/// [`crypto::aws_lc_rs::sign::any_ecdsa_type()`]: crate::crypto::aws_lc_rs::sign::any_ecdsa_type
/// [`crypto::aws_lc_rs::sign::any_eddsa_type()`]: crate::crypto::aws_lc_rs::sign::any_eddsa_type
/// [`crypto::aws_lc_rs::sign::any_supported_type()`]: crate::crypto::aws_lc_rs::sign::any_supported_type
/// [`ResolvesServerCertUsingSni`]: crate::server::ResolvesServerCertUsingSni
/// [`ResolvesServerCert`]: crate::server::ResolvesServerCert
/// [`ResolvesClientCert`]: crate::client::ResolvesClientCert
pub trait SigningKey: Debug + Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice by returning something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer: Debug + Send + Sync {
    /// Signs `message` using the selected scheme.
    ///
    /// `message` is not hashed; the implementer must hash it using the hash function
    /// implicit in [`Self::scheme()`].
    ///
    /// The returned signature format is also defined by [`Self::scheme()`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reveals which scheme will be used when you call [`Self::sign()`].
    fn scheme(&self) -> SignatureScheme;
}

#[derive(Clone, Debug)]
pub enum CertifiedKey {
    Mtc(MtcCertifiedKey),
    X509(X509CertifiedKey),
}

impl CertifiedKey {
    pub(crate) fn key(&self) -> &dyn SigningKey {
        match self {
            CertifiedKey::Mtc(c) => &*c.key,
            CertifiedKey::X509(c) => &*c.key,
        }
    }

    pub(crate) fn cert(&self) -> X509OrBikeshedCertChain {
        match self {
            CertifiedKey::Mtc(c) => X509OrBikeshedCertChain::Bikeshed(&c.cert),
            CertifiedKey::X509(c) => X509OrBikeshedCertChain::X509(&c.cert),
        }
    }
}

impl From<MtcCertifiedKey> for CertifiedKey {
    fn from(value: MtcCertifiedKey) -> Self {
        Self::Mtc(value)
    }
}

impl From<X509CertifiedKey> for CertifiedKey {
    fn from(value: X509CertifiedKey) -> Self {
        Self::X509(value)
    }
}

#[derive(Clone, Debug)]
pub struct MtcCertifiedKey {
    pub cert: BikeshedCertificate,

    pub key: Arc<dyn SigningKey>,
}

/// Contains either a X509 certificate chain or a Bikeshed certificate (which does not need a chain)
#[derive(Debug, Clone)]
pub enum X509OrBikeshedCertChain<'a> {
    X509(&'a [CertificateDer<'static>]),
    Bikeshed(&'a BikeshedCertificate),
}

impl Default for X509OrBikeshedCertChain<'static> {
    fn default() -> Self {
        Self::X509(&[])
    }
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response.
#[derive(Clone, Debug)]
pub struct X509CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<CertificateDer<'static>>,

    /// The certified key.
    pub key: Arc<dyn SigningKey>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,
}

impl X509CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            cert,
            key,
            ocsp: None,
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&CertificateDer<'_>, Error> {
        self.cert
            .first()
            .ok_or(Error::NoCertificatesPresented)
    }
}
