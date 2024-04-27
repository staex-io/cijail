use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::str::from_utf8;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use cijail::Answer;
use cijail::DnsName;
use cijail::DnsPacket;
use cijail::Name;
use cijail::Question;
use cijail::ResponseCode;
use cijail::Type;

pub(crate) struct DnsServer {
    socket: UdpSocket,
    records: HashMap<String, IpAddr>,
    stopped: AtomicBool,
}

impl DnsServer {
    pub(crate) fn new(records: HashMap<String, IpAddr>) -> (Arc<Self>, SocketAddr) {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)).unwrap();
        let socketaddr = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        (
            Arc::new(Self {
                socket,
                records,
                stopped: AtomicBool::new(false),
            }),
            socketaddr,
        )
    }

    pub(crate) fn spawn(self: Arc<DnsServer>) {
        std::thread::spawn(move || {
            self.run();
        });
    }

    fn run(&self) {
        while !self.stopped.load(Ordering::SeqCst) {
            let mut buffer = vec![0_u8; 4096];
            match self.socket.recv_from(buffer.as_mut_slice()) {
                Ok((size, socketaddr)) => {
                    buffer.truncate(size);
                    let (packet, _size) = DnsPacket::read(buffer.as_slice()).unwrap();
                    let mut packet = packet;
                    for question in packet.questions.iter() {
                        match self.new_answer(question) {
                            Ok(answer) => {
                                packet.answers.push(answer);
                            }
                            Err(code) => {
                                packet.header.set_response_code(code);
                                break;
                            }
                        }
                    }
                    packet.header.set_response();
                    buffer.resize(4096, 0);
                    let size = packet.write(buffer.as_mut_slice()).unwrap();
                    buffer.truncate(size);
                    self.socket.send_to(buffer.as_slice(), socketaddr).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    eprintln!("error {}", e);
                    break;
                }
            }
        }
    }

    pub(crate) fn stop(self: Arc<DnsServer>) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    fn new_answer(&self, question: &Question) -> Result<Answer, ResponseCode> {
        if !matches!(question.get_type(), Type::A | Type::Ptr) {
            Err(ResponseCode::Success)
        } else {
            let name =
                from_utf8(question.name.as_slice()).map_err(|_| ResponseCode::FormatError)?;
            let dns_name: DnsName = name.parse().map_err(|_| ResponseCode::FormatError)?;
            let address = self
                .records
                .get(dns_name.as_str())
                .ok_or(ResponseCode::NameError)?;
            Ok(Answer::from_ipaddr(
                Name::Pointer(question.name_offset),
                *address,
            ))
        }
    }
}
