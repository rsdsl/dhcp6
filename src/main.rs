use rsdsl_dhcp6::client::{Dhcp6c, Lease, Packet};
use rsdsl_dhcp6::util::*;
use rsdsl_dhcp6::{Error, Result};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::str::FromStr;
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, Duration, Instant};

use dhcproto::v6::{
    duid::Duid, DhcpOption, IAPrefix, Message, MessageType, OptionCode, Status, StatusCode, IAPD,
    ORO,
};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const DUID_LOCATION: &str = "/data/dhcp6.duid";
const INTERFACE: &str = "ppp0";

const ALL_DHCPV6_SERVERS: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2), 547, 0, 0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Dhcp6 {
    duid: Duid,
    lease: Option<PdConfig>,

    xid: [u8; 3],
    xts: Instant, // Transaction timestamp.
    server_id: Vec<u8>,
    last_sent: Packet,
    iapd: IAPD,
}

impl Dhcp6 {
    fn load_from_disk() -> Result<Self> {
        let lease = load_lease_optional();

        Ok(Self {
            duid: load_or_generate_duid()?,
            lease: lease.clone(),

            xid: rand::random(),
            xts: Instant::now(),
            server_id: lease
                .clone()
                .map(|lease| lease.server_id)
                .unwrap_or_default(),
            last_sent: Packet::Advertise, // Can never occur naturally, forces XID generation.
            iapd: lease
                .map(|lease| IAPD {
                    id: 1,
                    t1: 0,
                    t2: 0,
                    opts: vec![DhcpOption::IAPrefix(IAPrefix {
                        preferred_lifetime: 0,
                        valid_lifetime: 0,
                        prefix_len: lease.len,
                        prefix_ip: lease.prefix,
                        opts: Default::default(),
                    })]
                    .into_iter()
                    .collect(),
                })
                .unwrap_or(IAPD {
                    id: 1,
                    t1: 0,
                    t2: 0,
                    opts: Default::default(),
                }),
        })
    }
}

fn load_or_generate_duid() -> Result<Duid> {
    match fs::read(DUID_LOCATION) {
        Ok(duid) => Ok(duid.into()),
        Err(_) => {
            let duid = Duid::uuid(&rand::random::<u128>().to_be_bytes());
            fs::write(DUID_LOCATION, &duid)?;

            Ok(duid)
        }
    }
}

fn load_lease_optional() -> Option<PdConfig> {
    let mut file = File::open(rsdsl_pd_config::LOCATION).ok()?;
    let lease = serde_json::from_reader(&mut file).ok();

    lease.filter(|lease| !expired(lease))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[info] init");

    sleep(Duration::from_secs(1)).await;

    let mut dhcp6 = Dhcp6::load_from_disk()?;

    let mut dhcp6c = Dhcp6c::new(
        dhcp6.lease.clone().and_then(|lease| {
            Some(Lease {
                timestamp: sys_to_instant(lease.timestamp).ok()?,
                t1: Duration::from_secs(lease.t1.into()),
                t2: Duration::from_secs(lease.t2.into()),
                valid_lifetime: Duration::from_secs(lease.validlft.into()),
            })
        }),
        None,
        None,
    );
    let mut dhcp6c_rx = dhcp6c.opened();

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    sock.set_only_v6(true)?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;

    let address = SocketAddr::from_str("[::]:546")?;
    sock.bind(&address.into())?;

    let sock: std::net::UdpSocket = sock.into();
    sock.set_nonblocking(true)?;

    let sock: UdpSocket = sock.try_into()?;

    println!("[info] wait for pppoe");

    let mut already_up = true;
    while let Err(e) = sock.bind_device(Some(INTERFACE.as_bytes())) {
        if e.raw_os_error() == Some(19) {
            // "No such device" doesn't have an ErrorKind.
            already_up = false;
            sleep(Duration::from_secs(1)).await;
        } else {
            return Err(e.into());
        }
    }

    if already_up {
        println!("[info] <> ipv6 link already up");
        dhcp6c.up();
    }

    let mut buf = [0; 1500];
    loop {
        tokio::select! {
            biased;

            _ = sigusr1.recv() => {
                match read_ds_config() {
                    Some(ds_config) if ds_config.v6.is_some() => {
                        println!("[info] <> ipv6 link up");

                        sock.bind_device(Some(INTERFACE.as_bytes()))?;
                        dhcp6c.up();
                    }
                    _ => {
                        println!("[info] <> ipv6 link down");

                        sock.bind_device(None)?;
                        dhcp6c.down();
                    }
                }
            },
            _ = sigusr2.recv() => {
                if let Some(lease) = dhcp6c.lease() {
                    if let Some(pd_config) = dhcp6.lease.as_mut() {
                        pd_config.timestamp = SystemTime::now() - Instant::now().duration_since(lease.timestamp);

                        let mut file = File::create(rsdsl_pd_config::LOCATION)?;
                        serde_json::to_writer_pretty(&mut file, &pd_config)?;

                        println!("[info] <> update acquiration timestamp (ntp)");
                    }
                }
            },

            result = sock.recv_from(&mut buf) => {
                let (n, _) = result?;
                let buf = &buf[..n];

                logged_handle(&mut dhcp6, &mut dhcp6c, buf);
            }

            packet = dhcp6c.to_send() => send_dhcp6(&mut dhcp6, &sock, packet.0, packet.1).await,

            result = dhcp6c_rx.changed() => {
                result?;

                let is_opened = *dhcp6c_rx.borrow_and_update();
                if is_opened {
                    let pd_config = dhcp6.lease.clone().ok_or(Error::LeaseNotFound)?;

                    let mut file = File::create(rsdsl_pd_config::LOCATION)?;
                    serde_json::to_writer_pretty(&mut file, &pd_config)?;

                    inform();

                    println!(
                        "[info] <> obtain lease {}/{} t1={} t2={} preflft={} validlft={} dns1={} dns2={} aftr={:?}",
                        pd_config.prefix,
                        pd_config.len,
                        pd_config.t1,
                        pd_config.t2,
                        pd_config.preflft,
                        pd_config.validlft,
                        pd_config.dns1,
                        pd_config.dns2,
                        pd_config.aftr
                    );
                } else {
                    fs::remove_file(rsdsl_pd_config::LOCATION)?;
                    inform();

                    println!("[info] <> invalidate");
                }
            }
        }
    }
}

fn logged_handle(dhcp6: &mut Dhcp6, dhcp6c: &mut Dhcp6c, buf: &[u8]) {
    match handle(dhcp6, dhcp6c, buf) {
        Ok(_) => {}
        Err(e) => println!("[warn] {}", e),
    }
}

fn handle(dhcp6: &mut Dhcp6, dhcp6c: &mut Dhcp6c, buf: &[u8]) -> Result<()> {
    let msg = Message::decode(&mut Decoder::new(buf))?;
    let opts = msg.opts();

    let DhcpOption::ClientId(client_id) =
        opts.get(OptionCode::ClientId).ok_or(Error::NoClientId)?
    else {
        unreachable!()
    };

    let DhcpOption::ServerId(server_id) =
        opts.get(OptionCode::ServerId).ok_or(Error::NoServerId)?
    else {
        unreachable!()
    };

    if client_id != dhcp6.duid.as_ref() {
        return Err(Error::WrongClientId(
            hexdump(dhcp6.duid.as_ref()),
            hexdump(client_id),
        ));
    }

    if dhcp6c.accept_new_server_id() {
        dhcp6.server_id = server_id.to_vec();
    } else if server_id != &dhcp6.server_id {
        return Err(Error::WrongServerId(
            hexdump(&dhcp6.server_id),
            hexdump(server_id),
        ));
    }

    match msg.msg_type() {
        MessageType::Advertise => {
            let DhcpOption::IAPD(ia_pd) = opts.get(OptionCode::IAPD).ok_or(Error::NoIAPD)? else {
                unreachable!()
            };
            dhcp6.iapd = ia_pd.clone();

            dhcp6c.from_recv(Packet::Advertise);

            println!("[info] <- advertise");
        }
        MessageType::Reply => {
            let aftr_name = opts.get(OptionCode::AftrName).map(|v| {
                if let DhcpOption::Unknown(unk) = v {
                    Name::from_bytes(unk.data()).expect("invalid aftr name format")
                } else {
                    unreachable!()
                }
            });

            let DhcpOption::IAPD(ia_pd) = opts.get(OptionCode::IAPD).ok_or(Error::NoIAPD)? else {
                unreachable!()
            };
            let DhcpOption::IAPrefix(ia_prefix) = ia_pd
                .opts
                .get(OptionCode::IAPrefix)
                .ok_or(Error::NoIAPrefix)?
            else {
                unreachable!()
            };

            let DhcpOption::DomainNameServers(dnss) = opts
                .get(OptionCode::DomainNameServers)
                .ok_or(Error::NoDns)?
            else {
                unreachable!()
            };

            if dnss.len() < 2 {
                return Err(Error::TooFewDns(dnss.len()));
            }

            let DhcpOption::StatusCode(status) = opts
                .get(OptionCode::StatusCode)
                .cloned()
                .unwrap_or(DhcpOption::StatusCode(StatusCode {
                    status: Status::Success,
                    msg: String::from("success"),
                }))
            else {
                unreachable!()
            };

            let DhcpOption::StatusCode(status_ia_pd) = ia_pd
                .opts
                .get(OptionCode::StatusCode)
                .cloned()
                .unwrap_or(DhcpOption::StatusCode(StatusCode {
                    status: Status::Success,
                    msg: String::from("success"),
                }))
            else {
                unreachable!()
            };

            let DhcpOption::StatusCode(status_ia_prefix) = ia_prefix
                .opts
                .get(OptionCode::StatusCode)
                .cloned()
                .unwrap_or(DhcpOption::StatusCode(StatusCode {
                    status: Status::Success,
                    msg: String::from("success"),
                }))
            else {
                unreachable!()
            };

            let fail = status.status != Status::Success
                || status_ia_pd.status != Status::Success
                || status_ia_prefix.status != Status::Success;

            if status.status != Status::Success {
                println!("[warn] <- reply status {:?}: {}", status.status, status.msg);
            }

            if status_ia_pd.status != Status::Success {
                println!(
                    "[warn] <- reply ia_pd status {:?}: {}",
                    status_ia_pd.status, status_ia_pd.msg
                );
            }

            if status_ia_prefix.status != Status::Success {
                println!(
                    "[warn] <- reply ia_prefix status {:?}: {}",
                    status_ia_prefix.status, status_ia_prefix.msg
                );
            }

            if fail {
                return Ok(());
            }

            dhcp6.iapd = ia_pd.clone();

            dhcp6.lease = Some(PdConfig {
                timestamp: SystemTime::now(),
                server: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                server_id: dhcp6.server_id.clone(),
                t1: ia_pd.t1,
                t2: ia_pd.t2,
                prefix: ia_prefix.prefix_ip,
                len: ia_prefix.prefix_len,
                preflft: ia_prefix.preferred_lifetime,
                validlft: ia_prefix.valid_lifetime,
                dns1: dnss[0],
                dns2: dnss[1],
                aftr: aftr_name.map(|name| name.to_utf8()),
            });

            dhcp6c.from_recv(Packet::Reply(
                Lease {
                    timestamp: Instant::now(),
                    t1: Duration::from_secs(ia_pd.t1.into()),
                    t2: Duration::from_secs(ia_pd.t2.into()),
                    valid_lifetime: Duration::from_secs(ia_prefix.valid_lifetime.into()),
                },
                status.status == Status::NoBinding
                    || status_ia_pd.status == Status::NoBinding
                    || status_ia_prefix.status == Status::NoBinding,
            ));
        }
        _ => println!("[warn] <- unimplemented message type {:?}", msg.msg_type()),
    }

    Ok(())
}

async fn send_dhcp6(dhcp6: &mut Dhcp6, sock: &UdpSocket, packet: Packet, re_tx: bool) {
    match do_send_dhcp6(dhcp6, sock, packet, re_tx).await {
        Ok(_) => {}
        Err(e) => println!("[warn] -> send error: {}", e),
    }
}

async fn do_send_dhcp6(
    dhcp6: &mut Dhcp6,
    sock: &UdpSocket,
    packet: Packet,
    re_tx: bool,
) -> Result<()> {
    if !re_tx {
        dhcp6.xid = rand::random();
        dhcp6.xts = Instant::now();
    }

    let elapsed = Instant::now()
        .duration_since(dhcp6.xts)
        .as_millis()
        .try_into()
        .unwrap_or(u16::MAX);

    match packet {
        Packet::Solicit => {
            let prefix_len_hint = dhcp6.lease.as_ref().map(|pd_config| pd_config.len);
            let prefix_hint = dhcp6.lease.as_ref().map(|pd_config| pd_config.prefix);

            let mut solicit = Message::new_with_id(MessageType::Solicit, dhcp6.xid);
            let opts = solicit.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::RapidCommit);
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![
                    OptionCode::SolMaxRt,
                    OptionCode::InfMaxRt,
                    OptionCode::AftrName,
                    OptionCode::DomainNameServers,
                ],
            }));
            opts.insert(DhcpOption::ElapsedTime(elapsed));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: vec![DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                    prefix_len: prefix_len_hint.unwrap_or(56),
                    prefix_ip: prefix_hint.unwrap_or(Ipv6Addr::UNSPECIFIED),
                    opts: Default::default(),
                })]
                .into_iter()
                .collect(),
            }));

            let mut buf = Vec::new();
            solicit.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!(
                "[info] -> solicit hint {:?}",
                prefix_hint
                    .zip(prefix_len_hint)
                    .map(|hint| format!("{}/{}", hint.0, hint.1))
            );
        }
        Packet::Request => {
            let DhcpOption::IAPrefix(ia_prefix) = dhcp6
                .iapd
                .opts
                .get(OptionCode::IAPrefix)
                .ok_or(Error::NoIAPrefix)?
            else {
                unreachable!()
            };

            let mut request = Message::new_with_id(MessageType::Request, dhcp6.xid);
            let opts = request.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::ServerId(dhcp6.server_id.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![
                    OptionCode::SolMaxRt,
                    OptionCode::InfMaxRt,
                    OptionCode::AftrName,
                    OptionCode::DomainNameServers,
                ],
            }));
            opts.insert(DhcpOption::ElapsedTime(elapsed));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: vec![DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                    prefix_len: ia_prefix.prefix_len,
                    prefix_ip: ia_prefix.prefix_ip,
                    opts: Default::default(),
                })]
                .into_iter()
                .collect(),
            }));

            let mut buf = Vec::new();
            request.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> request");
        }
        Packet::Renew => {
            let DhcpOption::IAPrefix(ia_prefix) = dhcp6
                .iapd
                .opts
                .get(OptionCode::IAPrefix)
                .ok_or(Error::NoIAPrefix)?
            else {
                unreachable!()
            };

            let mut renew = Message::new_with_id(MessageType::Renew, dhcp6.xid);
            let opts = renew.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::ServerId(dhcp6.server_id.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![
                    OptionCode::SolMaxRt,
                    OptionCode::InfMaxRt,
                    OptionCode::AftrName,
                    OptionCode::DomainNameServers,
                ],
            }));
            opts.insert(DhcpOption::ElapsedTime(elapsed));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: vec![DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                    prefix_len: ia_prefix.prefix_len,
                    prefix_ip: ia_prefix.prefix_ip,
                    opts: Default::default(),
                })]
                .into_iter()
                .collect(),
            }));

            let mut buf = Vec::new();
            renew.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> renew");
        }
        Packet::Rebind => {
            let DhcpOption::IAPrefix(ia_prefix) = dhcp6
                .iapd
                .opts
                .get(OptionCode::IAPrefix)
                .ok_or(Error::NoIAPrefix)?
            else {
                unreachable!()
            };

            let mut rebind = Message::new_with_id(MessageType::Rebind, dhcp6.xid);
            let opts = rebind.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![
                    OptionCode::SolMaxRt,
                    OptionCode::InfMaxRt,
                    OptionCode::AftrName,
                    OptionCode::DomainNameServers,
                ],
            }));
            opts.insert(DhcpOption::ElapsedTime(elapsed));
            opts.insert(DhcpOption::IAPD(IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: vec![DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                    prefix_len: ia_prefix.prefix_len,
                    prefix_ip: ia_prefix.prefix_ip,
                    opts: Default::default(),
                })]
                .into_iter()
                .collect(),
            }));

            let mut buf = Vec::new();
            rebind.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> rebind");
        }
        _ => println!("[warn] -> can't send unsupported packet type"),
    }

    dhcp6.last_sent = packet;

    Ok(())
}
