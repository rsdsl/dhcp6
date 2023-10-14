use crate::{Error, Result};

use std::fs::File;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use tokio::net::{ToSocketAddrs, UdpSocket};

use dhcproto::v6::IAPrefix;
use rsdsl_pd_config::PdConfig;
use sysinfo::{ProcessExt, Signal, System, SystemExt};

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

pub fn inform() {
    for netlinkd in System::default().processes_by_exact_name("/bin/rsdsl_netlinkd") {
        netlinkd.kill_with(Signal::User1);
    }

    for dslite in System::default().processes_by_exact_name("/bin/rsdsl_dslite") {
        dslite.kill_with(Signal::User1);
    }
}
