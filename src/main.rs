use rsdsl_dhcp6::{Error, Result};

use std::ffi::CString;
use std::fs::{self, File};
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::time::{self, Duration, Instant};

use dhcproto::v6::{duid::Duid, DhcpOption, IAPrefix, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, SockAddr, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const DUID_LOCATION: &str = "/data/dhcp6.duid";
const TICK_INTERVAL: u64 = 60;

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
    serde_json::from_reader(&mut file).ok()
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

    let mut interval = time::interval(Duration::from_secs(TICK_INTERVAL));

    let mut buf = [0; 1500];
    loop {
        tokio::select! {
            result = sock.recv_from(&mut buf) => {
            }
            _ = interval.tick() => {
            }
        }
    }
}

async fn send_to_exact<A: ToSocketAddrs>(sock: &UdpSocket, buf: &[u8], target: A) -> Result<()> {
    let n = sock.send_to(buf, target).await?;
    if n != buf.len() {
        Err(Error::PartialSend)
    } else {
        Ok(())
    }
}

fn write_pdconfig(ia_prefix: &IAPrefix, dnss: &[Ipv6Addr], aftr: &Option<String>) -> Result<()> {
    let pdconfig = PdConfig {
        timestamp: SystemTime::now(),
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
