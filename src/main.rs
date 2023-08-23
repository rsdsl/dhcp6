use std::ffi::CString;
use std::fs::File;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::process;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dhcproto::v6::{duid::Duid, DhcpOption, IAPrefix, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_dhcp6::util::setsockopt;
use rsdsl_dhcp6::{Error, Result};
use rsdsl_ip_config::DsConfig;
use rsdsl_netlinkd::link;
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, SockAddr, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const BUFSIZE: usize = 1500;
const MAX_ATTEMPTS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Solicit(Vec<u8>),
    Request(Vec<u8>, Vec<u8>, [u8; 3], SocketAddrV6, IAPD, usize),
    Active(Vec<u8>, Vec<u8>, SocketAddrV6, IAPD, Instant, u32),
    Renew(Vec<u8>, Vec<u8>, SocketAddrV6, IAPD, usize),
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

    let mut file = File::open(rsdsl_ip_config::LOCATION)?;
    let dsconfig: DsConfig = serde_json::from_reader(&mut file)?;

    if dsconfig.v6.is_none() {
        println!("ignore incapable ppp0");

        loop {
            thread::sleep(Duration::MAX);
        }
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
            Err(e) => {
                println!("can't tick on ppp0: {}", e);
                process::exit(1);
            }
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
    let mut state = state.lock().expect("state mutex is poisoned");
    let msg = Message::decode(&mut Decoder::new(buf))?;

    let expected_client_id = match *state {
        State::Solicit(ref expected_client_id) => expected_client_id,
        State::Request(ref expected_client_id, ..) => expected_client_id,
        State::Active(ref expected_client_id, ..) => expected_client_id,
        State::Renew(ref expected_client_id, ..) => expected_client_id,
    };

    let client_id = match msg
        .opts()
        .get(OptionCode::ClientId)
        .ok_or(Error::NoClientId)?
    {
        DhcpOption::ClientId(client_id) => client_id,
        _ => unreachable!(),
    };

    if client_id != expected_client_id {
        println!(" <- [{}] invalid client id", remote);
        return Ok(());
    }

    match msg.msg_type() {
        MessageType::Advertise => {
            let opts = msg.opts();

            let server_id = match opts.get(OptionCode::ServerId).ok_or(Error::NoServerId)? {
                DhcpOption::ServerId(server_id) => server_id,
                _ => unreachable!(),
            };

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

            let dnss = match opts
                .get(OptionCode::DomainNameServers)
                .ok_or(Error::NoDns)?
            {
                DhcpOption::DomainNameServers(dnss) => dnss,
                _ => unreachable!(),
            };

            if dnss.len() < 2 {
                return Err(Error::TooFewDns(dnss.len()));
            }

            match *state {
                State::Solicit(ref client_id) => {
                    let mut request = Message::new_with_id(MessageType::Request, msg.xid());
                    let opts = request.opts_mut();

                    opts.insert(DhcpOption::ClientId(client_id.clone()));
                    opts.insert(DhcpOption::ServerId(server_id.clone()));
                    opts.insert(DhcpOption::IAPD(ia_pd.clone()));
                    opts.insert(DhcpOption::ORO(ORO {
                        opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
                    }));

                    let mut request_buf = Vec::new();
                    request.encode(&mut Encoder::new(&mut request_buf))?;

                    send_to_exact(sock, &request_buf, &remote.into())?;

                    println!(
                        " <- [{}] advertise pd {}/{} valid {} pref {}, dns1 {}, dns2 {}, aftr {}",
                        remote,
                        ia_prefix.prefix_ip,
                        ia_prefix.prefix_len,
                        ia_prefix.valid_lifetime,
                        ia_prefix.preferred_lifetime,
                        dnss[0],
                        dnss[1],
                        aftr.map(|v| v.to_utf8()).unwrap_or("unset".into())
                    );
                    println!(
                        " -> [{}] request 0/{} pd {}, dns, aftr",
                        remote, MAX_ATTEMPTS, ia_pd.id
                    );

                    *state = State::Request(
                        client_id.clone(),
                        server_id.clone(),
                        msg.xid(),
                        remote,
                        ia_pd.clone(),
                        1,
                    );
                }
                _ => println!(" <- [{}] unexpected advertise", remote),
            }
        }
        MessageType::Reply => {
            let opts = msg.opts();

            let rapid_commit = opts.get(OptionCode::RapidCommit).is_some();

            let server_id = match opts.get(OptionCode::ServerId).ok_or(Error::NoServerId)? {
                DhcpOption::ServerId(server_id) => server_id,
                _ => unreachable!(),
            };

            let aftr = opts.get(OptionCode::AftrName).map(|v| match v {
                DhcpOption::Unknown(unk) => {
                    Name::from_bytes(unk.data()).expect("invalid aftr name format")
                }
                _ => unreachable!(),
            });

            match *state {
                State::Solicit(ref client_id) => {
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

                    let dnss = match opts
                        .get(OptionCode::DomainNameServers)
                        .ok_or(Error::NoDns)?
                    {
                        DhcpOption::DomainNameServers(dnss) => dnss,
                        _ => unreachable!(),
                    };

                    if dnss.len() < 2 {
                        return Err(Error::TooFewDns(dnss.len()));
                    }

                    let aftr = aftr.map(|v| v.to_utf8());

                    if !rapid_commit {
                        println!(" <- [{}] unexpected reply rapid commit, pd {}/{} valid {} pref {}, dns1 {}, dns2 {}, aftr {}", remote, ia_prefix.prefix_ip, ia_prefix.prefix_len, ia_prefix.valid_lifetime, ia_prefix.preferred_lifetime, dnss[0], dnss[1], aftr.clone().unwrap_or("unset".into()));
                        return Ok(());
                    }

                    println!(" <- [{}] reply rapid commit, pd {}/{} valid {} pref {}, dns1 {}, dns2 {}, aftr {}", remote, ia_prefix.prefix_ip, ia_prefix.prefix_len, ia_prefix.valid_lifetime, ia_prefix.preferred_lifetime, dnss[0], dnss[1], aftr.clone().unwrap_or("unset".into()));
                    *state = State::Active(
                        client_id.clone(),
                        server_id.clone(),
                        remote,
                        ia_pd.clone(),
                        Instant::now(),
                        ia_pd.t1,
                    );

                    update_pdconfig(ia_prefix, dnss, &aftr);
                }
                State::Request(ref client_id, ref expected_server_id, ..) => {
                    if server_id != expected_server_id {
                        println!(" <- [{}] reply from invalid server id", remote);
                        return Ok(());
                    }

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

                    let dnss = match opts
                        .get(OptionCode::DomainNameServers)
                        .ok_or(Error::NoDns)?
                    {
                        DhcpOption::DomainNameServers(dnss) => dnss,
                        _ => unreachable!(),
                    };

                    if dnss.len() < 2 {
                        return Err(Error::TooFewDns(dnss.len()));
                    }

                    let aftr = aftr.map(|v| v.to_utf8());

                    println!(
                        " <- [{}] reply pd {}/{} valid {} pref {}, dns1 {}, dns2 {}, aftr {}",
                        remote,
                        ia_prefix.prefix_ip,
                        ia_prefix.prefix_len,
                        ia_prefix.valid_lifetime,
                        ia_prefix.preferred_lifetime,
                        dnss[0],
                        dnss[1],
                        aftr.clone().unwrap_or("unset".into())
                    );
                    *state = State::Active(
                        client_id.clone(),
                        server_id.clone(),
                        remote,
                        ia_pd.clone(),
                        Instant::now(),
                        ia_pd.t1,
                    );

                    update_pdconfig(ia_prefix, dnss, &aftr);
                }
                State::Renew(ref client_id, ref expected_server_id, _, ref ia_pd, _) => {
                    if server_id != expected_server_id {
                        println!(" <- [{}] reply renew from invalid server id", remote);
                        return Ok(());
                    }

                    println!(
                        " <- [{}] reply renew pd {}, dns1, dns2, aftr",
                        remote, ia_pd.id,
                    );
                    *state = State::Active(
                        client_id.clone(),
                        server_id.clone(),
                        remote,
                        ia_pd.clone(),
                        Instant::now(),
                        ia_pd.t1,
                    );
                }
                _ => println!(" <- [{}] unexpected reply", remote),
            }
        }
        MessageType::Decline => {
            let client_id = match *state {
                State::Solicit(ref client_id) => client_id,
                State::Request(ref client_id, ..) => client_id,
                State::Active(ref client_id, ..) => client_id,
                State::Renew(ref client_id, ..) => client_id,
            };

            let expected_server_id = match *state {
                State::Solicit(..) => None,
                State::Request(_, ref expected_server_id, ..) => Some(expected_server_id),
                State::Active(_, ref expected_server_id, ..) => Some(expected_server_id),
                State::Renew(_, ref expected_server_id, ..) => Some(expected_server_id),
            };

            if let Some(expected_server_id) = expected_server_id {
                let server_id = match msg
                    .opts()
                    .get(OptionCode::ServerId)
                    .ok_or(Error::NoServerId)?
                {
                    DhcpOption::ServerId(server_id) => server_id,
                    _ => unreachable!(),
                };

                if server_id != expected_server_id {
                    println!(" <- [{}] decline from invalid server id", remote);
                    return Ok(());
                }
            }

            *state = State::Solicit(client_id.clone());
            println!(" <- [{}] decline", remote);
        }
        _ => println!(" <- [{}] invalid message type {:?}", remote, msg.msg_type()),
    }

    Ok(())
}

fn tick(sock: &Socket, state: Arc<Mutex<State>>) -> Result<()> {
    let mut state = state.lock().expect("state mutex is poisoned");
    match *state {
        State::Solicit(ref client_id) => {
            let dst: SocketAddrV6 = "[ff02::1:2]:547".parse()?;

            let mut solicit = Message::new(MessageType::Solicit);
            let opts = solicit.opts_mut();

            opts.insert(DhcpOption::ClientId(client_id.clone()));
            opts.insert(DhcpOption::RapidCommit);
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: Default::default(),
            }));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut solicit_buf = Vec::new();
            solicit.encode(&mut Encoder::new(&mut solicit_buf))?;

            send_to_exact(sock, &solicit_buf, &dst.into())?;

            println!(" -> [{}] solicit rapid commit, pd 1, dns, aftr", dst);
            Ok(())
        }
        State::Request(ref client_id, ref server_id, xid, dst, ref ia_pd, n) => {
            if n >= MAX_ATTEMPTS {
                *state = State::Solicit(client_id.clone());

                println!("<-> request retransmission maximum exceeded");
                return Ok(());
            }

            let mut request = Message::new_with_id(MessageType::Request, xid);
            let opts = request.opts_mut();

            opts.insert(DhcpOption::ClientId(client_id.clone()));
            opts.insert(DhcpOption::ServerId(server_id.clone()));
            opts.insert(DhcpOption::IAPD(ia_pd.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut request_buf = Vec::new();
            request.encode(&mut Encoder::new(&mut request_buf))?;

            send_to_exact(sock, &request_buf, &dst.into())?;

            println!(
                " -> [{}] request {}/{} pd {}, dns, aftr",
                dst, n, MAX_ATTEMPTS, ia_pd.id
            );

            *state = State::Request(
                client_id.clone(),
                server_id.clone(),
                xid,
                dst,
                ia_pd.clone(),
                n + 1,
            );
            Ok(())
        }
        State::Active(ref client_id, ref server_id, dst, ref ia_pd, recv, t1) => {
            // Subtraction accounts for delay causey by loop interval.
            if Instant::now().duration_since(recv).as_secs() >= (t1 - 3).into() {
                let mut expired_pd = ia_pd.clone();
                let expired_prefix = match expired_pd
                    .opts
                    .get_mut(OptionCode::IAPrefix)
                    .ok_or(Error::NoIAPrefix)?
                {
                    DhcpOption::IAPrefix(expired_prefix) => expired_prefix,
                    _ => unreachable!(),
                };

                expired_pd.t1 = 0;
                expired_pd.t2 = 0;
                expired_prefix.preferred_lifetime = 0;
                expired_prefix.valid_lifetime = 0;

                *state = State::Renew(client_id.clone(), server_id.clone(), dst, expired_pd, 0);
            }

            Ok(())
        }
        State::Renew(ref client_id, ref server_id, dst, ref ia_pd, n) => {
            if n >= MAX_ATTEMPTS {
                *state = State::Solicit(client_id.clone());

                println!("<-> renew retransmission maximum exceeded");
                return Ok(());
            }

            let mut renew = Message::new(MessageType::Renew);
            let opts = renew.opts_mut();

            opts.insert(DhcpOption::ClientId(client_id.clone()));
            opts.insert(DhcpOption::ServerId(server_id.clone()));
            opts.insert(DhcpOption::IAPD(ia_pd.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut renew_buf = Vec::new();
            renew.encode(&mut Encoder::new(&mut renew_buf))?;

            send_to_exact(sock, &renew_buf, &dst.into())?;

            println!(
                " -> [{}] renew {}/{} pd {}, dns, aftr",
                dst, n, MAX_ATTEMPTS, ia_pd.id
            );

            *state = State::Renew(
                client_id.clone(),
                server_id.clone(),
                dst,
                ia_pd.clone(),
                n + 1,
            );
            Ok(())
        }
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

fn update_pdconfig(ia_prefix: &IAPrefix, dnss: &[Ipv6Addr], aftr: &Option<String>) {
    match write_pdconfig(ia_prefix, dnss, aftr) {
        Ok(_) => println!("<-> write pd config to {}", rsdsl_pd_config::LOCATION),
        Err(e) => println!(
            "<-> can't write pd config to {}: {}",
            rsdsl_pd_config::LOCATION,
            e
        ),
    }
}

fn write_pdconfig(ia_prefix: &IAPrefix, dnss: &[Ipv6Addr], aftr: &Option<String>) -> Result<()> {
    let pdconfig = PdConfig {
        prefix: ia_prefix.prefix_ip,
        len: ia_prefix.prefix_len,
        validlft: ia_prefix.valid_lifetime,
        preflft: ia_prefix.preferred_lifetime,
        dns1: dnss[0], // Bounds checked by packet handler.
        dns2: dnss[1], // Bounds checked by packet handler.
        aftr: aftr.clone(),
    };

    let mut file = File::create(rsdsl_pd_config::LOCATION)?;
    serde_json::to_writer_pretty(&mut file, &pdconfig)?;

    Ok(())
}
