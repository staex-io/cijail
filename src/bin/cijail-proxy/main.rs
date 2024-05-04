use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;

use cijail::env_to_bool;
use cijail::EndpointSet;
use cijail::Logger;
use cijail::Uri;
use cijail::CIJAIL_DRY_RUN;
use cijail::CIJAIL_ENDPOINTS;
use http::uri::PathAndQuery;
use http::uri::Scheme;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1 as http1_client;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_rustls::ConfigBuilderExt;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::Connect;
use hyper_util::rt::TokioIo;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use log::error;
use log::info;
use socketpair::SocketpairStream;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Logger::init("cijail-proxy").map_err(|_| "failed to set logger")?;
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to initi crypto provider")?;
    let tls_config = rustls::ClientConfig::builder()
        .with_native_roots()?
        .with_no_client_auth();
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, hyper::body::Incoming> =
        Client::builder(TokioExecutor::new()).build(https);
    let client = Arc::new(client);
    let is_dry_run = env_to_bool(CIJAIL_DRY_RUN)?;
    let allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(string) => EndpointSet::from_base64(string.as_str())?,
        Err(_) => Default::default(),
    };
    let http_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let http_socketaddr = http_listener.local_addr()?;
    info!("listening for http connections on {}", http_socketaddr);
    let https_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let https_socketaddr = https_listener.local_addr()?;
    info!("listening for https connections on {}", https_socketaddr);
    let mut socket = unsafe { SocketpairStream::from_raw_fd(0) };
    socket.write_all(http_socketaddr.port().to_ne_bytes().as_slice())?;
    socket.write_all(https_socketaddr.port().to_ne_bytes().as_slice())?;
    drop(socket);
    let context = Arc::new(Context {
        allowed_endpoints,
        is_dry_run,
    });
    loop {
        tokio::select! {
            result = http_listener.accept() => {
                let (stream, _) = result?;
                let io = TokioIo::new(stream);
                let context = context.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(err) = http1_server::Builder::new()
                        .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(
                                io,
                                service_fn(move |request| {
                                    proxy(request, context.clone(), client.clone())
                                }),
                            )
                            .with_upgrades()
                            .await
                    {
                        info!("Failed to serve connection: {:?}", err);
                    }
                });
            }
            _result = https_listener.accept() => {
            }
        }
    }
}

async fn proxy<T: Connect + Clone + Send + Sync + 'static>(
    request: Request<hyper::body::Incoming>,
    context: Arc<Context>,
    client: Arc<Client<T, hyper::body::Incoming>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, cijail::Error> {
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
    info!("uri {}", uri);
    let result = match do_proxy(request, &uri, context.clone(), client).await {
        Err(cijail::Error::Deny) => {
            let response = Response::new(Bytes::from("cijail: denied"));
            let (mut parts, body) = response.into_parts();
            parts.status = StatusCode::IM_A_TEAPOT;
            let response = Response::from_parts(parts, body);
            Ok((
                response.map(|b| Full::new(b).map_err(|e| match e {}).boxed()),
                false,
            ))
        }
        other => other,
    };
    match result {
        Ok((response, allow)) => {
            print_decision(context.is_dry_run, allow, &uri, response.status())?;
            Ok(response)
        }
        Err(e) => Err(e),
    }
}

async fn do_proxy<T: Connect + Clone + Send + Sync + 'static>(
    request: Request<hyper::body::Incoming>,
    uri: &Uri,
    context: Arc<Context>,
    client: Arc<Client<T, hyper::body::Incoming>>,
) -> Result<(Response<BoxBody<Bytes, hyper::Error>>, bool), cijail::Error> {
    let allow = context.allowed_endpoints.contains_uri(uri);
    if !context.is_dry_run && !allow {
        return Err(cijail::Error::Deny);
    }
    let stream = TcpStream::connect((uri.host.as_str(), uri.port)).await?;
    let io = TokioIo::new(stream);
    let response = match uri.scheme.as_str() {
        "http" => {
            // TODO replace with `client`
            let (mut sender, conn) = http1_client::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    error!("failed to connect: {}", e);
                }
            });
            let response = sender.send_request(request).await?;
            response.map(|b| (b.boxed()))
        }
        "https" => {
            if request.method() == "CONNECT" {
                let socketaddrs = context.allowed_endpoints.resolve_dns_name(&uri.host);
                if socketaddrs.is_empty() || !socketaddrs.iter().any(|x| x.port() == uri.port) {
                    return Err(cijail::Error::Deny);
                }
                let socketaddr = socketaddrs[0];
                tokio::spawn(async move {
                    match hyper::upgrade::on(request).await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, socketaddr).await {
                                error!("server io error: {}", e);
                            };
                        }
                        Err(e) => error!("upgrade error: {}", e),
                    }
                });
                Response::new(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed(),
                )
            } else {
                let response = client.request(request).await?;
                response.map(|x| x.boxed())
            }
        }
        _ => {
            return Err(cijail::Error::Deny);
        }
    };
    Ok((response, allow))
}

async fn tunnel(upgraded: Upgraded, socketaddr: SocketAddr) -> std::io::Result<()> {
    let mut server = TcpStream::connect(socketaddr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

fn print_decision(
    is_dry_run: bool,
    allow: bool,
    uri: &Uri,
    status: StatusCode,
) -> Result<(), std::fmt::Error> {
    use std::fmt::Write;
    let mut buf = String::with_capacity(4096);
    if is_dry_run {
        write!(&mut buf, "DRYRUN ")?;
    }
    write!(&mut buf, "{}", if allow { "allow" } else { "deny" })?;
    write!(&mut buf, " {} {}", status.as_u16(), uri)?;
    info!("{}", buf);
    Ok(())
}

struct Context {
    allowed_endpoints: EndpointSet,
    is_dry_run: bool,
}
