mod ech_config {
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::handshake::EchConfigPayload;
    use rustls::pki_types::EchConfigListBytes;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use trust_dns_resolver::proto::rr::{RData, RecordType};
    use trust_dns_resolver::Resolver;

    #[test]
    fn cloudflare() {
        test_deserialize_ech_config_list("crypto.cloudflare.com");
    }

    #[test]
    fn defo_ie() {
        test_deserialize_ech_config_list("defo.ie");
    }

    #[test]
    fn tls_ech_dev() {
        test_deserialize_ech_config_list("tls-ech.dev");
    }

    /// Lookup the ECH config list for a domain and deserialize it.
    fn test_deserialize_ech_config_list(domain: &str) {
        let resolver = Resolver::new(ResolverConfig::google(), ResolverOpts::default()).unwrap();
        let tls_encoded_list = lookup_ech(&resolver, domain);
        let parsed_configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&tls_encoded_list))
            .expect("failed to deserialize ECH config list");
        assert!(!parsed_configs.is_empty());
        assert!(parsed_configs
            .iter()
            .all(|config| matches!(config, EchConfigPayload::V18(_))));
    }

    /// Use `resolver` to make an HTTPS record type query for `domain`, returning the
    /// first SvcParam EchConfig value found, panicing if none are returned.
    fn lookup_ech(resolver: &Resolver, domain: &str) -> EchConfigListBytes<'static> {
        resolver
            .lookup(domain, RecordType::HTTPS)
            .expect("failed to lookup HTTPS record type")
            .record_iter()
            .find_map(|r| match r.data() {
                Some(RData::HTTPS(svcb)) => svcb
                    .svc_params()
                    .iter()
                    .find_map(|sp| match sp {
                        (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                            Some(e.clone().0)
                        }
                        _ => None,
                    }),
                _ => None,
            })
            .expect("missing expected HTTPS SvcParam EchConfig record")
            .into()
    }
}
