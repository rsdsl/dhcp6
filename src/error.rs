use std::{io, net, time};

use tokio::sync::watch;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("lease has been obtained but doesn't exist")]
    LeaseNotFound,
    #[error("server did not include a client id option")]
    NoClientId,
    #[error("server did not include a domain name servers option")]
    NoDns,
    #[error("server did not include an ia_pd option")]
    NoIAPD,
    #[error("server did not include an ia_prefix option in the ia_pd option")]
    NoIAPrefix,
    #[error("server did not include a server id option")]
    NoServerId,
    #[error("unable to send full packet (expected {0}, got {1})")]
    PartialSend(usize, usize),
    #[error("too few domain name servers (expected at least 2, got {0})")]
    TooFewDns(usize),
    #[error("received packet with wrong client duid (expected {0}, got {1})")]
    WrongClientId(String, String),
    #[error("received packet with wrong server duid (expected {0}, got {1})")]
    WrongServerId(String, String),

    #[error("can't parse network address: {0}")]
    AddrParse(#[from] net::AddrParseError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("system time monotonicity error: {0}")]
    SystemTime(#[from] time::SystemTimeError),

    #[error("can't receive from tokio watch channel: {0}")]
    WatchRecv(#[from] watch::error::RecvError),

    #[error("dhcproto decode error: {0}")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("dhcproto encode error: {0}")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
