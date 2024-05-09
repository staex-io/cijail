use std::fmt::Display;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

use bincode::decode_from_std_read;
use bincode::encode_into_std_write;
use bincode::Decode;
use bincode::Encode;
use log::info;

use crate::Error;
use crate::SSL_CERT_FILE;

#[derive(Encode, Decode)]
pub struct ProxyConfig {
    pub http_url: ProxyUrl,
    pub https_url: ProxyUrl,
    pub ssl_cert_file_path: PathBuf,
}

impl ProxyConfig {
    pub fn setenv(&self, command: &mut Command) {
        for name in ["http_proxy", "HTTP_PROXY"] {
            command.env(name, self.http_url.to_string());
        }
        for name in ["https_proxy", "HTTPS_PROXY"] {
            command.env(name, self.https_url.to_string());
        }
        for name in ["no_proxy", "NO_PROXY"] {
            command.env_remove(name);
        }
        {
            let path = self.ssl_cert_file_path.as_path();
            command.env(SSL_CERT_FILE, path);
            command.env("GIT_SSL_CAINFO", path);
            command.env("PIP_CERT", path);
            command.env("NODE_EXTRA_CA_CERTS", path);
        }
        for (name, value) in command.get_envs() {
            let name = name.to_string_lossy();
            match value {
                Some(value) => info!("set {} = {}", name, value.to_string_lossy()),
                None => info!("unset {}", name),
            }
        }
    }

    pub fn write<W: Write>(&self, stream: &mut W) -> Result<(), Error> {
        encode_into_std_write(self, stream, bincode::config::standard())?;
        Ok(())
    }

    pub fn read<R: Read>(stream: &mut R) -> Result<Self, Error> {
        Ok(decode_from_std_read(stream, bincode::config::standard())?)
    }
}

#[derive(Encode, Decode)]
pub struct ProxyUrl {
    pub scheme: String,
    pub socketaddr: SocketAddr,
}

impl Display for ProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.socketaddr)
    }
}
