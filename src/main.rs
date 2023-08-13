use std::ffi::CString;
use std::fs::File;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dhcproto::v6::{DhcpOption, Message, MessageType, IAPD};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use rsdsl_dhcp6::util::setsockopt;
use rsdsl_dhcp6::{Error, Result};
use rsdsl_ip_config::DsConfig;
use rsdsl_netlinkd::link;
use socket2::{Domain, SockAddr, Socket, Type};

const BUFSIZE: usize = 1500;

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Solicit(Vec<u8>),
    Request,
    Active,
    Renew,
}

impl Default for State {
    fn default() -> Self {
        Self::Solicit(rand::random::<u128>().to_be_bytes().to_vec())
    }
}

fn main() -> Result<()> {
    println!("wait for up ppp0");
    link::wait_up("ppp0".into())?;

    let mut file = File::open("/tmp/pppoe.ip_config")?;
    let ds_config: DsConfig = serde_json::from_reader(&mut file)?;

    if ds_config.v6.is_none() {
        println!("ignore incapable ppp0");
    }

    println!("init ppp0");

    let state = Arc::new(Mutex::new(State::default()));

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    sock.set_only_v6(true)?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;

    // Bind socket to interface.
    unsafe {
        let link_index = CString::new("ppp0")?.into_raw();

        setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            link_index,
            "ppp0".len() as i32,
        )?;

        // Prevent memory leak.
        let _ = CString::from_raw(link_index);
    }

    let address = SocketAddr::from_str("[::]:546")?;
    sock.bind(&address.into())?;

    let sock2 = sock.try_clone()?;
    thread::spawn(move || loop {
        match tick(&sock2, state.clone()) {
            Ok(_) => thread::sleep(Duration::from_secs(3)),
            Err(e) => println!("can't tick on ppp0: {}", e),
        }
    });

    loop {
        let mut buf = [MaybeUninit::new(0); BUFSIZE];
        let (n, remote) = sock.recv_from(&mut buf)?;
        let buf = &buf
            .iter()
            .take(n)
            .map(|p| unsafe { p.assume_init() })
            .collect::<Vec<u8>>();

        let remote = remote.as_socket_ipv6().unwrap();

        match handle_response(&sock, buf) {
            Ok(_) => {}
            Err(e) => println!("can't handle pkt from {} on ppp0: {}", remote, e),
        }
    }
}

fn handle_response(sock: &Socket, buf: &[u8]) -> Result<()> {
    // let dst: SocketAddrV6 = "[ff02::1:2]:547".parse()?;

    // let msg = Message::decode(&mut Decoder::new(buf))?;

    // let typ = msg.msg_type();
    // match typ {
    //     MessageType::Advertise => {}
    // }

    Ok(())
}

fn tick(sock: &Socket, state: Arc<Mutex<State>>) -> Result<()> {
    let dst: SocketAddrV6 = "[ff02::1:2]:547".parse()?;

    let state = state.lock().expect("state mutex is poisoned");
    match *state {
        State::Solicit(ref client_id) => {
            let mut req = Message::new(MessageType::Solicit);
            let opts = req.opts_mut();

            opts.insert(DhcpOption::ClientId(client_id.clone()));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: Default::default(),
            }));

            let mut req_buf = Vec::new();
            req.encode(&mut Encoder::new(&mut req_buf))?;

            sock.send_to(&req_buf, &dst.into())?;

            println!("solicit pd 1 aftr");
            Ok(())
        }
        _ => todo!(),
    }
}

fn send_to_exact(sock: &Socket, buf: &[u8], dst: &SockAddr) -> Result<()> {
    let n = sock.send_to(buf, dst)?;
    if n != buf.len() {
        Err(Error::PartialSend)
    } else {
        Ok(())
    }
}
