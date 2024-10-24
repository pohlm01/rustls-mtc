use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::server::ClientHello;
use crate::{server, sign, CertificateType};

/// Something which never stores sessions.
#[derive(Debug)]
pub struct NoServerSessionStorage {}

impl server::StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod cache {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::fmt::{Debug, Formatter};

    use crate::lock::Mutex;
    use crate::{limited_cache, server};

    /// An implementer of `StoresServerSessions` that stores everything
    /// in memory.  If enforces a limit on the number of stored sessions
    /// to bound memory usage.
    pub struct ServerSessionMemoryCache {
        cache: Mutex<limited_cache::LimitedCache<Vec<u8>, Vec<u8>>>,
    }

    impl ServerSessionMemoryCache {
        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(feature = "std")]
        pub fn new(size: usize) -> Arc<Self> {
            Arc::new(Self {
                cache: Mutex::new(limited_cache::LimitedCache::new(size)),
            })
        }

        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(not(feature = "std"))]
        pub fn new<M: crate::lock::MakeMutex>(size: usize) -> Arc<Self> {
            Arc::new(Self {
                cache: Mutex::new::<M>(limited_cache::LimitedCache::new(size)),
            })
        }
    }

    impl server::StoresServerSessions for ServerSessionMemoryCache {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.cache
                .lock()
                .unwrap()
                .insert(key, value);
            true
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache
                .lock()
                .unwrap()
                .get(key)
                .cloned()
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache.lock().unwrap().remove(key)
        }

        fn can_cache(&self) -> bool {
            true
        }
    }

    impl Debug for ServerSessionMemoryCache {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ServerSessionMemoryCache")
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::vec;

        use super::*;
        use crate::server::StoresServerSessions;

        #[test]
        fn test_serversessionmemorycache_accepts_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_persists_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_overwrites_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x01], vec![0x04]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
        }

        #[test]
        fn test_serversessionmemorycache_drops_to_maintain_size_invariant() {
            let c = ServerSessionMemoryCache::new(2);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x03], vec![0x04]));
            assert!(c.put(vec![0x05], vec![0x06]));
            assert!(c.put(vec![0x07], vec![0x08]));
            assert!(c.put(vec![0x09], vec![0x0a]));

            let count = c.get(&[0x01]).iter().count()
                + c.get(&[0x03]).iter().count()
                + c.get(&[0x05]).iter().count()
                + c.get(&[0x07]).iter().count()
                + c.get(&[0x09]).iter().count();

            assert!(count < 5);
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use cache::ServerSessionMemoryCache;

/// Something which never produces tickets.
#[derive(Debug)]
pub(super) struct NeverProducesTickets {}

impl server::ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Something which always resolves to the same cert chain.
#[derive(Debug)]
pub struct AlwaysResolvesChain(Arc<sign::CertifiedKey>);

impl AlwaysResolvesChain {
    /// Creates an `AlwaysResolvesChain`, using the supplied `CertifiedKey`.
    pub fn new(certified_key: sign::CertifiedKey) -> Self {
        Self(Arc::new(certified_key))
    }

    /// Creates an `AlwaysResolvesChain`, using the supplied `CertifiedKey` and OCSP response.
    ///
    /// If non-empty, the given OCSP response is attached.
    pub fn new_with_extras(certified_key: sign::CertifiedKey, ocsp: Vec<u8>) -> Self {
        let mut r = Self::new(certified_key);

        {
            let cert = Arc::make_mut(&mut r.0);
            if !ocsp.is_empty() {
                cert.set_ocsp(ocsp);
            }
        }

        r
    }
}

impl server::ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// An exemplar `ResolvesServerCert` implementation that always resolves to a single
/// [RFC 7250] raw public key.  
///
/// [RFC 7250]: https://tools.ietf.org/html/rfc7250  
#[derive(Clone, Debug)]
pub struct AlwaysResolvesServerRawPublicKeys(Arc<sign::CertifiedKey>);

impl AlwaysResolvesServerRawPublicKeys {
    /// Create a new `AlwaysResolvesServerRawPublicKeys` instance.
    pub(crate) fn new(certified_key: Arc<sign::CertifiedKey>) -> Self {
        Self(certified_key)
    }
}

impl server::ResolvesServerCert for AlwaysResolvesServerRawPublicKeys {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn supported_cert_types(&self) -> &[CertificateType] {
        &[CertificateType::RawPublicKey]
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod sni_resolver {
    use alloc::string::{String, ToString};
    use alloc::sync::Arc;
    use core::fmt::Debug;

    use pki_types::{DnsName, ServerName};

    use crate::error::Error;
    use crate::hash_map::HashMap;
    use crate::server::ClientHello;
    use crate::webpki::{verify_server_name, ParsedCertificate};
    use crate::{server, sign};

    /// Something that resolves do different cert chains/keys based
    /// on client-supplied server name (via SNI).
    #[derive(Debug)]
    pub struct ResolvesServerCertUsingSni {
        by_name: HashMap<String, Arc<sign::CertifiedKey>>,
    }

    impl ResolvesServerCertUsingSni {
        /// Create a new and empty (i.e., knows no certificates) resolver.
        pub fn new() -> Self {
            Self {
                by_name: HashMap::new(),
            }
        }

        /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
        ///
        /// This function fails if `name` is not a valid DNS name, or if
        /// it's not valid for the supplied certificate, or if the certificate
        /// chain is syntactically faulty.
        pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
            let server_name = {
                let checked_name = DnsName::try_from(name)
                    .map_err(|_| Error::General("Bad DNS name".into()))
                    .map(|name| name.to_lowercase_owned())?;
                ServerName::DnsName(checked_name)
            };

            // Check the certificate chain for validity:
            // - it should be non-empty list
            // - the first certificate should be parsable as a x509v3,
            // - the first certificate should quote the given server name
            //   (if provided)
            //
            // These checks are not security-sensitive.  They are the
            // *server* attempting to detect accidental misconfiguration.

            ck.end_entity_cert()
                .and_then(ParsedCertificate::try_from)
                .and_then(|cert| verify_server_name(&cert, &server_name))?;

            if let ServerName::DnsName(name) = server_name {
                self.by_name
                    .insert(name.as_ref().to_string(), Arc::new(ck));
            }
            Ok(())
        }
    }

    impl server::ResolvesServerCert for ResolvesServerCertUsingSni {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
            if let Some(name) = client_hello.server_name() {
                self.by_name.get(name).cloned()
            } else {
                // This kind of resolver requires SNI
                None
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::server::ResolvesServerCert;

        #[test]
        fn test_resolvesservercertusingsni_requires_sni() {
            let rscsni = ResolvesServerCertUsingSni::new();
            assert!(rscsni
                .resolve(ClientHello::new(&None, &[], None, None, None, &[], None))
                .is_none());
        }

        #[test]
        fn test_resolvesservercertusingsni_handles_unknown_name() {
            let rscsni = ResolvesServerCertUsingSni::new();
            let name = DnsName::try_from("hello.com")
                .unwrap()
                .to_owned();
            assert!(rscsni
                .resolve(ClientHello::new(
                    &Some(name),
                    &[],
                    None,
                    None,
                    None,
                    &[],
                    None
                ))
                .is_none());
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use sni_resolver::ResolvesServerCertUsingSni;

mod tai_resolver {
    use crate::crypto::CryptoProvider;
    use crate::msgs::codec::Codec;
    use crate::server::handy::tai_resolver::BikeshedServerFile::{CaParams, Cert, PrivateKey};
    use crate::server::ClientHello;
    use crate::sign::CertifiedKey;
    use crate::{server, sign, BikeshedCertificate, Error, TrustAnchorIdentifier};
    use alloc::vec::Vec;
    use core::fmt::Debug;
    use log::warn;
    use pki_types::pem::PemObject;
    use pki_types::PrivateKeyDer;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::{dbg, fs, vec};

    /// Something that resolves do different certificates and keys based
    /// on client-supplied supported Trust Anchor Identifiers (TAI).
    /// If the TAI is not known to the resolver, it will use the fallback server cert resolver.
    #[derive(Debug)]
    pub(crate) struct ResolvesServerCertUsingTaiWithFallback {
        by_tai: HashMap<TrustAnchorIdentifier, Arc<CertifiedKey>>,
        mtc_dir: PathBuf,
        crypto_provider: Arc<CryptoProvider>,
        fallback: Arc<dyn server::ResolvesServerCert>,
    }

    impl ResolvesServerCertUsingTaiWithFallback {
        /// Create a new and empty (i.e., knows no certificates) resolver.
        pub(crate) fn new(
            mtc_dir: PathBuf,
            crypto_provider: Arc<CryptoProvider>,
            fallback: Arc<dyn server::ResolvesServerCert>,
        ) -> Self {
            let mut res = Self {
                by_tai: HashMap::new(),
                mtc_dir,
                crypto_provider,
                fallback,
            };
            res.load_bikeshed_certs_from_disk();
            res
        }

        pub fn load_bikeshed_certs_from_disk(&mut self) {
            let files = match fs::read_dir(&self.mtc_dir) {
                Ok(files) => files,
                Err(err) => {
                    warn!("Could not update Bikeshed certificates: {err}");
                    return;
                }
            };

            let mut certs = vec![];
            let mut private_key = None;

            for file in files.filter(Result::is_ok) {
                // This `unwrap` is safe as all `Err` values have been filtered in the `for` loop
                let path = file.unwrap().path();
                if let Some(file) = read_file(&path) {
                    match file {
                        Cert(c) => certs.push(c),
                        CaParams(_) => {}
                        PrivateKey(k) => {
                            if private_key.is_some() {
                                warn!("Duplicate private key found");
                            } else {
                                private_key = Some(k);
                            }
                        }
                    }
                }
            }

            assert!(private_key.is_some());
            let key = self
                .crypto_provider
                .key_provider
                .load_private_key(private_key.unwrap())
                .unwrap();

            self.by_tai
                .extend(certs.into_iter().map(|cert| {
                    (
                        dbg!(cert.tai()),
                        Arc::new(CertifiedKey::Bikeshed {
                            cert,
                            key: Arc::clone(&key),
                        }),
                    )
                }));
        }

        /// Add a new [`CertifiedKey`] to be used for the given TAI.
        ///
        /// This function fails if `tai` is not a valid TrustAnchorIdentifier or if the certificate
        /// chain is syntactically faulty.
        pub(crate) fn add(&mut self, tai: &str, ck: CertifiedKey) -> Result<(), Error> {
            // TODO @max proper error handling and check if provided certificates are valid, etc.
            let tai: TrustAnchorIdentifier = tai.parse().unwrap();

            self.by_tai.insert(tai, Arc::new(ck));
            Ok(())
        }
    }

    enum BikeshedServerFile {
        Cert(BikeshedCertificate),
        CaParams(Vec<u8>),
        PrivateKey(PrivateKeyDer<'static>),
    }

    fn read_file(path: &Path) -> Option<BikeshedServerFile> {
        let file_name = path.file_name()?.to_str()?;
        if file_name == "ca_params" {
            let mut f = File::open(path).ok()?;
            let mut bytes = vec![];
            f.read_to_end(&mut bytes).ok()?;
            Some(CaParams(bytes))
        } else if file_name.ends_with(".mtc") {
            let mut f = File::open(path).ok()?;
            let mut bytes = vec![];
            f.read_to_end(&mut bytes).ok()?;
            Some(Cert(BikeshedCertificate::read_bytes(&bytes).unwrap()))
        } else if file_name.ends_with(".pem") {
            Some(PrivateKey(dbg!(PrivateKeyDer::from_pem_file(path)).ok()?))
        } else {
            None
        }
    }

    impl server::ResolvesServerCert for ResolvesServerCertUsingTaiWithFallback {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            if let Some(tais) = client_hello.supported_trust_anchors() {
                for tai in tais {
                    if let Some(cert) = self.by_tai.get(dbg!(tai)) {
                        return Some(Arc::clone(cert));
                    }
                }
            };
            self.fallback.resolve(client_hello)
        }
    }
}

pub(crate) use tai_resolver::ResolvesServerCertUsingTaiWithFallback;

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::server::{ProducesTickets, StoresServerSessions};

    #[test]
    fn test_noserversessionstorage_drops_put() {
        let c = NoServerSessionStorage {};
        assert!(!c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_noserversessionstorage_denies_gets() {
        let c = NoServerSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_noserversessionstorage_denies_takes() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.take(&[]), None);
        assert_eq!(c.take(&[0x01]), None);
        assert_eq!(c.take(&[0x02]), None);
    }

    #[test]
    fn test_neverproducestickets_does_nothing() {
        let npt = NeverProducesTickets {};
        assert!(!npt.enabled());
        assert_eq!(0, npt.lifetime());
        assert_eq!(None, npt.encrypt(&[]));
        assert_eq!(None, npt.decrypt(&[]));
    }
}
