//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::env;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_file(true)
                .with_line_number(true),
        )
        .with(EnvFilter::from_default_env())
        .init();

    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();

    let mut mtc_cert_data = File::open(cert_file).unwrap();
    let mut cert = vec![];
    mtc_cert_data.read_to_end(&mut cert)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_mtc_cert("62253.12.15.1", cert, private_key)?;

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut stream, _) = listener.accept()?;

    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;
    conn.complete_io(&mut stream)?;

    conn.writer()
        .write_all(b"Hello from the server")?;
    conn.complete_io(&mut stream)?;
    let mut buf = [0; 64];
    let len = conn.reader().read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}
