use cijail::env_to_bool;
use cijail::EndpointSet;
use http::uri::PathAndQuery;
use http::uri::Scheme;
use hyper::body::Incoming;
use hyper::StatusCode;
use rcgen::CertifiedKey;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use cijail::Error;
use cijail::Logger;
use cijail::ProxyConfig;
use cijail::ProxyUrl;
use cijail::Uri;
use cijail::CIJAIL_DRY_RUN;
use cijail::CIJAIL_ENDPOINTS;
use cijail::CIJAIL_ROOT_CERT_PEM;
use cijail::SSL_CERT_FILE;
use http_mitm_proxy::futures::StreamExt;
use http_mitm_proxy::MitmProxy;
use hyper::Request;
use log::info;
use socketpair::SocketpairStream;
use tempfile::NamedTempFile;
use tokio_native_tls::native_tls::TlsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Logger::init("cijail-proxy").map_err(|_| "failed to set logger")?;
    let is_dry_run = env_to_bool(CIJAIL_DRY_RUN)?;
    let allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(string) => EndpointSet::from_base64(string.as_str())?,
        Err(_) => Default::default(),
    };
    let root_cert = make_root_cert()?;
    let root_cert_pem = root_cert.cert.pem();
    std::env::set_var(CIJAIL_ROOT_CERT_PEM, root_cert_pem.as_str());
    let ssl_cert_file = add_root_ca_to_openssl_cert_file(root_cert_pem.as_str())?;
    let socketaddr = random_socketaddr()?;
    let proxy = MitmProxy::new(Some(root_cert), TlsConnector::new()?);
    let (mut communications, server) = proxy.bind(socketaddr).await?;
    tokio::spawn(server);
    {
        let config = ProxyConfig {
            http_url: ProxyUrl {
                scheme: "http".into(),
                socketaddr,
            },
            https_url: ProxyUrl {
                scheme: "http".into(),
                socketaddr,
            },
            ssl_cert_file_path: ssl_cert_file.path().into(),
        };
        let mut socket = unsafe { SocketpairStream::from_raw_fd(0) };
        config.write(&mut socket)?;
    }
    while let Some(comm) = communications.next().await {
        let uri = get_uri(&comm.request)?;
        let allow = allowed_endpoints.contains_uri(&uri);
        let status = if allow || is_dry_run {
            let _ = comm.request_back.send(comm.request);
            match comm.response.await {
                Ok(Ok(response)) => Some(response.status()),
                _ => None,
            }
        } else {
            None
        };
        print_decision(is_dry_run, allow, &uri, status)?;
    }
    Ok(())
}

fn make_root_cert() -> Result<CertifiedKey, Error> {
    let mut param = rcgen::CertificateParams::default();
    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<Cijail CA>".to_string()),
    );
    param.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = param.self_signed(&key_pair)?;
    Ok(CertifiedKey { cert, key_pair })
}

fn random_socketaddr() -> Result<SocketAddr, cijail::Error> {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let socketaddr = listener.local_addr()?;
    Ok(socketaddr)
}

fn add_root_ca_to_openssl_cert_file(root_cert_pem: &str) -> Result<NamedTempFile, Error> {
    let original_path = get_openssl_cert_file_path()?;
    info!("openssl cert file: {}", original_path.display());
    let mut named_temp_file = NamedTempFile::new()?;
    let mut new_file = named_temp_file.as_file_mut();
    let mut original_file = File::open(original_path)?;
    std::io::copy(&mut original_file, &mut new_file)?;
    writeln!(&mut new_file, "{}", root_cert_pem)?;
    Ok(named_temp_file)
}

fn get_openssl_cert_file_path() -> Result<PathBuf, Error> {
    match std::env::var_os(SSL_CERT_FILE) {
        Some(file) => Ok(Path::new(file.as_os_str()).into()),
        None => {
            let mut command = Command::new("openssl");
            command.args(["version", "-d"]);
            let args = get_args(&command);
            let output = command
                .output()
                .map_err(|e| Error::map(format!("failed to run `openssl` command: {}", e)))?;
            match output.status.code() {
                None => {
                    return Err(Error::map(format!(
                        "failed to run `{}`: terminated by signal",
                        args
                    )))
                }
                Some(ret) if ret != 0 => {
                    return Err(Error::map(format!(
                        "failed to run `{}`: exit code {}",
                        args, ret
                    )));
                }
                _ => {}
            }
            let i = output.stdout.iter().position(|ch| ch == &b'"');
            let j = output.stdout.iter().rposition(|ch| ch == &b'"');
            match (i, j) {
                (Some(i), Some(j)) => {
                    let s = OsStr::from_bytes(&output.stdout[(i + 1)..j]);
                    let openssl_dir = Path::new(s);
                    for suffix in [
                        "certs/ca-certificates.crt", // deb-based distributions
                        "certs/ca-bundle.crt",       // rpm-based distributions
                        "cert.pem",                  // rpm-based distributions
                    ] {
                        let path = openssl_dir.join(suffix);
                        if path.exists() {
                            return Ok(path);
                        }
                    }
                    Err(Error::map(format!(
                        "Failed to find CA bundle in `{}`. Please, specify it for cijail using {} variable.",
                        openssl_dir.display(),
                        SSL_CERT_FILE,
                    )))
                }
                _ => Err(Error::map(format!(
                    "invalid output from `{}`: `{}`",
                    args,
                    String::from_utf8_lossy(output.stdout.as_slice()).trim()
                ))),
            }
        }
    }
}

fn get_args(command: &Command) -> String {
    let mut args: Vec<String> = Vec::new();
    args.push(command.get_program().to_string_lossy().to_string());
    args.extend(command.get_args().map(|x| x.to_string_lossy().to_string()));
    args.join(" ")
}

fn get_uri(request: &Request<Incoming>) -> Result<Uri, cijail::Error> {
    let uri = request.uri();
    let uri = if uri.scheme_str().is_some() {
        uri.to_owned()
    } else {
        let mut parts = uri.to_owned().into_parts();
        parts.scheme = Some(Scheme::HTTPS);
        if parts.path_and_query.is_none() {
            parts.path_and_query = Some(PathAndQuery::from_static(""));
        }
        hyper::Uri::from_parts(parts)?
    };
    let uri: Uri = uri.try_into()?;
    Ok(uri)
}

fn print_decision(
    is_dry_run: bool,
    allow: bool,
    uri: &Uri,
    status: Option<StatusCode>,
) -> Result<(), std::fmt::Error> {
    use std::fmt::Write;
    let mut buf = String::with_capacity(4096);
    if is_dry_run {
        write!(&mut buf, "DRYRUN ")?;
    }
    write!(&mut buf, "{}", if allow { "allow" } else { "deny" })?;
    match status {
        Some(status) => write!(&mut buf, " {}", status.as_u16())?,
        None => write!(&mut buf, " -")?,
    }
    write!(&mut buf, " {}", uri)?;
    info!("{}", buf);
    Ok(())
}
