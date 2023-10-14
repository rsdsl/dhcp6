use std::time::{Duration, SystemTime};

use rsdsl_pd_config::PdConfig;

pub fn expired(lease: &PdConfig) -> bool {
    let expiry = lease.timestamp + Duration::from_secs(lease.preflft.into());
    SystemTime::now() >= expiry
}
