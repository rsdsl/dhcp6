use crate::{Error, Result};

use std::fs::File;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use tokio::net::{ToSocketAddrs, UdpSocket};

use dhcproto::v6::IAPrefix;
use rsdsl_pd_config::PdConfig;

pub fn expired(lease: &PdConfig) -> bool {
    let expiry = lease.timestamp + Duration::from_secs(lease.preflft.into());
    SystemTime::now() >= expiry
}

pub async fn send_to_exact<A: ToSocketAddrs>(
    sock: &UdpSocket,
    buf: &[u8],
    target: A,
) -> Result<()> {
    let n = sock.send_to(buf, target).await?;
    if n != buf.len() {
        Err(Error::PartialSend)
    } else {
        Ok(())
    }
}

pub fn write_pdconfig(
    ia_prefix: &IAPrefix,
    dnss: &[Ipv6Addr],
    aftr: &Option<String>,
) -> Result<()> {
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
