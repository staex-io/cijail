use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;

use cijail::env_to_bool;
use cijail::EndpointSet;
use cijail::Logger;
use cijail::CIJAIL_DRY_RUN;
use cijail::CIJAIL_ENDPOINTS;
use http_body_util::{combinators::BoxBody, BodyExt, Either, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1 as http1_client;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::Uri;
use hyper_util::rt::TokioIo;
use log::error;
use log::info;
use socketpair::SocketpairStream;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Logger::init("cijail-proxy").map_err(|_| "failed to set logger")?;
    let is_dry_run = env_to_bool(CIJAIL_DRY_RUN)?;
    let allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(string) => EndpointSet::from_base64(string.as_str())?,
        Err(_) => Default::default(),
    };
    let allowed_endpoints = Arc::new(allowed_endpoints);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let socketaddr = listener.local_addr()?;
    info!("listening on {}", socketaddr);
    let mut socket = unsafe { SocketpairStream::from_raw_fd(0) };
    socket.write_all(socketaddr.port().to_ne_bytes().as_slice())?;
    drop(socket);
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let allowed_endpoints = allowed_endpoints.clone();
        tokio::spawn(async move {
            if let Err(err) = http1_server::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |request| {
                        proxy(request, allowed_endpoints.clone(), is_dry_run)
                    }),
                )
                .with_upgrades()
                .await
            {
                info!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn proxy(
    request: Request<hyper::body::Incoming>,
    allowed_endpoints: Arc<EndpointSet>,
    is_dry_run: bool,
) -> Result<Response<Either<BoxBody<Bytes, hyper::Error>, Full<Bytes>>>, cijail::Error> {
    let uri = request.uri().to_owned();
    let allow;
    let response = if !is_dry_run && !allowed_endpoints.contains_uri(request.uri()) {
        let response = Response::new(Bytes::from("cijail: denied"));
        let (mut parts, body) = response.into_parts();
        parts.status = StatusCode::IM_A_TEAPOT;
        let response = Response::from_parts(parts, body);
        allow = false;
        response.map(|b| Either::Right(Full::new(b)))
    } else if let Some(host) = request.uri().host() {
        let port = request.uri().port_u16().unwrap_or(80);
        let stream = TcpStream::connect((host, port)).await?;
        let io = TokioIo::new(stream);
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
        allow = is_dry_run;
        response.map(|b| Either::Left(b.boxed()))
    } else {
        let response = Response::new(Bytes::from("cijail: denied"));
        let (mut parts, body) = response.into_parts();
        parts.status = StatusCode::IM_A_TEAPOT;
        let response = Response::from_parts(parts, body);
        allow = false;
        response.map(|b| Either::Right(Full::new(b)))
    };
    print_decision(is_dry_run, allow, &uri, response.status())?;
    Ok(response)
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
