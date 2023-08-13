use std::ffi::CString;
use std::fs::File;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dhcproto::v6::{duid::Duid, DhcpOption, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_dhcp6::util::setsockopt;
use rsdsl_dhcp6::{Error, Result};
use rsdsl_ip_config::DsConfig;
use rsdsl_netlinkd::link;
use socket2::{Domain, SockAddr, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const BUFSIZE: usize = 1500;

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Solicit(Vec<u8>),
    Request(Vec<u8>, SocketAddrV6),
    Active(Vec<u8>, SocketAddrV6),
    Renew(Vec<u8>, SocketAddrV6),
}

impl Default for State {
    fn default() -> Self {
        Self::Solicit(
            Duid::uuid(&rand::random::<u128>().to_be_bytes())
                .as_ref()
                .to_vec(),
        )
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
    let state2 = state.clone();
    thread::spawn(move || loop {
        match tick(&sock2, state2.clone()) {
            Ok(_) => {}
            Err(e) => println!("can't tick on ppp0: {}", e),
        }

        thread::sleep(Duration::from_secs(3));
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

        match handle_response(&sock, buf, remote, state.clone()) {
            Ok(_) => {}
            Err(e) => println!("can't handle pkt from {} on ppp0: {}", remote, e),
        }
    }
}

fn handle_response(
    sock: &Socket,
    buf: &[u8],
    remote: SocketAddrV6,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    let msg = Message::decode(&mut Decoder::new(buf))?;

    let mut state = state.lock().expect("state mutex is poisoned");
    match msg.msg_type() {
        MessageType::Advertise => {
            let opts = msg.opts();

            let aftr = opts.get(OptionCode::AftrName).map(|v| match v {
                DhcpOption::Unknown(unk) => {
                    Name::from_bytes(unk.data()).expect("invalid aftr name format")
                }
                _ => unreachable!(),
            });

            let ia_pd = match opts.get(OptionCode::IAPD).ok_or(Error::NoIAPD)? {
                DhcpOption::IAPD(ia_pd) => ia_pd,
                _ => unreachable!(),
            };

            let ia_prefix = match ia_pd
                .opts
                .get(OptionCode::IAPrefix)
                .ok_or(Error::NoIAPrefix)?
            {
                DhcpOption::IAPrefix(ia_prefix) => ia_prefix,
                _ => unreachable!(),
            };

            match *state {
                State::Solicit(ref client_id) => {
                    let mut request = Message::new(MessageType::Request);
                    let opts = request.opts_mut();

                    opts.insert(DhcpOption::ClientId(client_id.clone()));
                    opts.insert(DhcpOption::IAPD(ia_pd.clone()));
                    opts.insert(DhcpOption::ORO(ORO {
                        opts: vec![OptionCode::AftrName],
                    }));

                    let mut request_buf = Vec::new();
                    request.encode(&mut Encoder::new(&mut request_buf))?;

                    send_to_exact(sock, &request_buf, &remote.into())?;

                    *state = State::Request(client_id.clone(), remote);

                    println!(
                        " <- [{}] advertise pd {}/{} valid {} pref {}, aftr {}",
                        remote,
                        ia_prefix.prefix_ip,
                        ia_prefix.prefix_len,
                        ia_prefix.valid_lifetime,
                        ia_prefix.preferred_lifetime,
                        aftr.map(|v| v.to_utf8()).unwrap_or("unset".into())
                    );
                    println!(" -> [{}] request pd 1 aftr", remote);
                }
                _ => println!(" <- [{}] unexpected advertise from", remote),
            }
        }
        _ => todo!(),
    }

    Ok(())
}

fn tick(sock: &Socket, state: Arc<Mutex<State>>) -> Result<()> {
    let state = state.lock().expect("state mutex is poisoned");
    match *state {
        State::Solicit(ref client_id) => {
            let dst: SocketAddrV6 = "[ff02::1:2]:547".parse()?;

            let mut req = Message::new(MessageType::Solicit);
            let opts = req.opts_mut();

            opts.insert(DhcpOption::ClientId(client_id.clone()));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: Default::default(),
            }));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName],
            }));

            let mut req_buf = Vec::new();
            req.encode(&mut Encoder::new(&mut req_buf))?;

            send_to_exact(sock, &req_buf, &dst.into())?;

            println!(" -> solicit pd 1 aftr");
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
