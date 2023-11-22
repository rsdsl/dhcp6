use crate::{Error, Result};

use std::fs::File;
use std::time::{Duration, SystemTime};

use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::time::Instant;

use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use sysinfo::{ProcessExt, Signal, System, SystemExt};

pub fn expired(lease: &PdConfig) -> bool {
    let expiry = lease.timestamp + Duration::from_secs(lease.validlft.into());
    SystemTime::now() >= expiry
}

pub fn needs_rebind(lease: &PdConfig) -> bool {
    let expiry = lease.timestamp + Duration::from_secs(lease.t2.into());
    SystemTime::now() >= expiry
}

pub fn needs_renewal(lease: &PdConfig) -> bool {
    let expiry = lease.timestamp + Duration::from_secs(lease.t1.into());
    SystemTime::now() >= expiry
}

pub async fn send_to_exact<A: ToSocketAddrs>(
    sock: &UdpSocket,
    buf: &[u8],
    target: A,
) -> Result<()> {
    let n = sock.send_to(buf, target).await?;
    if n != buf.len() {
        Err(Error::PartialSend(buf.len(), n))
    } else {
        Ok(())
    }
}

pub fn inform() {
    for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
        netlinkd.kill_with(Signal::User1);
    }

    for dslite in System::new_all().processes_by_exact_name("rsdsl_dslite") {
        dslite.kill_with(Signal::User1);
    }
}

pub fn hexdump<A: AsRef<[u8]>>(data: A) -> String {
    data.as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .reduce(|acc, ch| acc + &ch)
        .unwrap_or(String::new())
}

pub fn sys_to_instant(sys: SystemTime) -> Result<Instant> {
    Ok(Instant::now() - sys.elapsed()?)
}

pub fn read_ds_config() -> Option<DsConfig> {
    let mut file = File::open(rsdsl_ip_config::LOCATION).ok()?;
    let ds_config = serde_json::from_reader(&mut file).ok()?;

    Some(ds_config)
}
