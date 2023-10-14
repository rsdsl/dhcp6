use rsdsl_dhcp6::util::setsockopt;
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
use std::time::{Duration, Instant, SystemTime};

use dhcproto::v6::{duid::Duid, DhcpOption, IAPrefix, Message, MessageType, OptionCode, IAPD, ORO};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use socket2::{Domain, SockAddr, Socket, Type};
use trust_dns_proto::serialize::binary::BinDecodable;

const BUFSIZE: usize = 1500;
const DUID_LOCATION: &str = "/data/dhcp6.duid";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Dhcp6 {
    duid: Duid,
    lease: Option<PdConfig>,
}

impl Dhcp6 {
    fn load_from_disk() -> Result<Self> {
        let mut lease_file = File::open(rsdsl_pd_config::LOCATION)?;

        Ok(Self {
            duid: load_or_generate_duid()?,
            lease: load_lease_optional(),
        })
    }
}

fn load_or_generate_duid() -> Result<Duid> {
    match fs::read("/data/dhcp6.duid") {
        Ok(duid) => Ok(duid.into()),
        Err(_) => {
            let duid = Duid::uuid(&rand::random::<u128>().to_be_bytes());
            fs::write("/data/dhcp6.duid", &duid)?;

            Ok(duid)
        }
    }
}

fn load_lease_optional() -> Option<PdConfig> {
    let mut file = File::open(rsdsl_pd_config::LOCATION).ok()?;
    serde_json::from_reader(&mut file).ok()
}

fn main() -> Result<()> {
    let dhcp6 = Dhcp6::load_from_disk()?;

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

    loop {
        let mut buf = [MaybeUninit::new(0); BUFSIZE];
        let (n, remote) = sock.recv_from(&mut buf)?;

        // See unstable `MaybeUninit::slice_assume_init_ref`.
        let buf = unsafe { &*(&buf as *const [MaybeUninit<u8>] as *const [u8]) };

        let buf = &buf[..n];
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
