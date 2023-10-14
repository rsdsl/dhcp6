use rsdsl_dhcp6::util::*;
use rsdsl_dhcp6::{Error, Result};

use std::fs::{self, File};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::str::FromStr;
use std::time::SystemTime;

use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::time::{self, Duration, Instant};

use dhcproto::v6::{duid::Duid, DhcpOption, IAPrefix, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, Socket, Type};
use sysinfo::{ProcessExt, Signal, System, SystemExt};
use trust_dns_proto::serialize::binary::BinDecodable;

const DUID_LOCATION: &str = "/data/dhcp6.duid";
const TICK_INTERVAL: u64 = 60;

const ALL_DHCPV6_SERVERS: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2), 547, 0, 0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Dhcp6 {
    duid: Duid,
    lease: Option<PdConfig>,
}

impl Dhcp6 {
    fn load_from_disk() -> Result<Self> {
        Ok(Self {
            duid: load_or_generate_duid()?,
            lease: load_lease_optional(),
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
    let dhcp6 = Dhcp6::load_from_disk()?;

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    sock.set_only_v6(true)?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;

    let address = SocketAddr::from_str("[::]:546")?;
    sock.bind(&address.into())?;

    let sock: std::net::UdpSocket = sock.into();
    let sock: UdpSocket = sock.try_into()?;

    sock.bind_device(Some("ppp0".as_bytes()))?;

    // If a valid lease is present on disk, inform netlinkd immediately.
    if dhcp6.lease.is_some() {
        for netlinkd in System::default().processes_by_exact_name("/bin/rsdsl_netlinkd") {
            netlinkd.kill_with(Signal::User1);
        }
    }

    let mut interval = time::interval(Duration::from_secs(TICK_INTERVAL));

    let mut buf = [0; 1500];
    loop {
        tokio::select! {
            result = sock.recv_from(&mut buf) => {
                let (n, raddr) = result?;
                let buf = &buf[..n];

                logged_handle(&dhcp6, buf, raddr);
                logged_tick(&sock, &dhcp6).await;
            }
            _ = interval.tick() => {
                logged_tick(&sock, &dhcp6).await;
            }
        }
    }
}

async fn logged_tick(sock: &UdpSocket, dhcp6: &Dhcp6) {
    match tick(sock, dhcp6).await {
        Ok(_) => {}
        Err(e) => println!("[warn] tick: {}", e),
    }
}

async fn tick(sock: &UdpSocket, dhcp6: &Dhcp6) -> Result<()> {
    match &dhcp6.lease {
        None => {
            let mut solicit = Message::new(MessageType::Solicit);
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
            Ok(())
        }
        Some(lease) => todo!(),
    }
}

fn logged_handle(dhcp6: &Dhcp6, buf: &[u8], raddr: SocketAddr) {
    match handle(dhcp6, buf, raddr) {
        Ok(_) => {}
        Err(e) => println!("[warn] handle from {}: {}", raddr, e),
    }
}

fn handle(dhcp6: &Dhcp6, buf: &[u8], raddr: SocketAddr) -> Result<()> {
    let msg = Message::decode(&mut Decoder::new(buf))?;

    let client_id = match msg
        .opts()
        .get(OptionCode::ClientId)
        .ok_or(Error::NoClientId)?
    {
        DhcpOption::ClientId(client_id) => client_id,
        _ => unreachable!(),
    };

    if client_id != dhcp6.duid.as_ref() {
        println!("[warn] <- [{}] client id mismatch", raddr);
        return Ok(());
    }

    match msg.msg_type() {
        _ => println!(
            "[warn] <- [{}] unhandled message type {:?}",
            raddr,
            msg.msg_type()
        ),
    }

    Ok(())
}
