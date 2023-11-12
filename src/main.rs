use rsdsl_dhcp6::client::{Dhcp6c, Lease, Packet};
use rsdsl_dhcp6::util::*;
use rsdsl_dhcp6::{Error, Result};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::str::FromStr;
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::time::Duration;

use dhcproto::v6::{duid::Duid, DhcpOption, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const DUID_LOCATION: &str = "/data/dhcp6.duid";

const ALL_DHCPV6_SERVERS: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2), 547, 0, 0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Dhcp6 {
    duid: Duid,
    lease: Option<PdConfig>,

    xid: [u8; 3],
    server_id: Vec<u8>,
    last_packet: Packet,
    iapd: IAPD,
}

impl Dhcp6 {
    fn load_from_disk() -> Result<Self> {
        Ok(Self {
            duid: load_or_generate_duid()?,
            lease: load_lease_optional(),

            xid: [0; 3],
            server_id: Vec::default(),
            last_packet: Packet::Reply, // Can never occur naturally, forces XID generation.
            iapd: IAPD {
                id: 1,
                t1: 0,
                t2: 0,
                opts: Default::default(),
            },
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

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    sock.set_only_v6(true)?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;

    let address = SocketAddr::from_str("[::]:546")?;
    sock.bind(&address.into())?;

    let sock: std::net::UdpSocket = sock.into();
    let sock: UdpSocket = sock.try_into()?;

    sock.bind_device(Some("ppp0".as_bytes()))?;

    let mut buf = [0; 1500];
    loop {
        tokio::select! {
            biased;

            packet = dhcp6c.to_send() => send_dhcp6(&mut dhcp6, &sock, packet).await?,

            result = dhcp6c_rx.changed() => {
                result?;

                let is_opened = *dhcp6c_rx.borrow_and_update();
                if is_opened {
                    todo!("write lease + inform")
                } else {
                    todo!("del lease + inform")
                }
            }

            Ok(result) = sock.recv_from(&mut buf) => {
                let (n, _) = result;
                let buf = &buf[..n];

                logged_handle(&mut dhcp6, &mut dhcp6c, buf);
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
            hexdump(client_id)?,
            hexdump(dhcp6.duid.as_ref())?,
        ));
    }

    if dhcp6c.is_soliciting() {
        dhcp6.server_id = server_id.to_vec();
    } else if server_id != &dhcp6.server_id {
        return Err(Error::WrongServerId(
            hexdump(server_id)?,
            hexdump(&dhcp6.server_id)?,
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

            dhcp6c.from_recv(Packet::Reply);
        }
        _ => println!("[warn] <- unimplemented message type {:?}", msg.msg_type()),
    }

    Ok(())
}

async fn send_dhcp6(dhcp6: &mut Dhcp6, sock: &UdpSocket, packet: Packet) -> Result<()> {
    if packet != dhcp6.last_packet {
        dhcp6.xid = rand::random();
    }

    match packet {
        Packet::Solicit => {
            let mut solicit = Message::new_with_id(MessageType::Solicit, dhcp6.xid);
            let opts = solicit.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
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

            let mut buf = Vec::new();
            solicit.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> solicit");
        }
        Packet::Request => {
            let mut request = Message::new_with_id(MessageType::Request, dhcp6.xid);
            let opts = request.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::ServerId(dhcp6.server_id.clone()));
            opts.insert(DhcpOption::IAPD(dhcp6.iapd.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut buf = Vec::new();
            request.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> request");
        }
        Packet::Renew => {
            let mut renew = Message::new_with_id(MessageType::Renew, dhcp6.xid);
            let opts = renew.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::ServerId(dhcp6.server_id.clone()));
            opts.insert(DhcpOption::IAPD(dhcp6.iapd.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut buf = Vec::new();
            renew.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> renew");
        }
        Packet::Rebind => {
            let mut rebind = Message::new_with_id(MessageType::Rebind, dhcp6.xid);
            let opts = rebind.opts_mut();

            opts.insert(DhcpOption::ClientId(dhcp6.duid.as_ref().to_vec()));
            opts.insert(DhcpOption::IAPD(dhcp6.iapd.clone()));
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![OptionCode::AftrName, OptionCode::DomainNameServers],
            }));

            let mut buf = Vec::new();
            rebind.encode(&mut Encoder::new(&mut buf))?;

            send_to_exact(sock, &buf, ALL_DHCPV6_SERVERS).await?;

            println!("[info] -> rebind");
        }
        _ => println!("[warn] -> can't send unsupported packet type"),
    }

    dhcp6.last_packet = packet;

    Ok(())
}
