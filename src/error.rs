use std::{ffi, io, net, time};

use tokio::sync::watch;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("lease has been obtained but doesn't exist")]
    LeaseNotFound,
    #[error("no client duid")]
    NoClientId,
    #[error("no hexdump data")]
    NoData,
    #[error("no domain name servers")]
    NoDns,
    #[error("no ia_pd")]
    NoIAPD,
    #[error("no ia_pd status code")]
    NoIAPDStatus,
    #[error("no ia_prefix")]
    NoIAPrefix,
    #[error("no server duid")]
    NoServerId,
    #[error("incomplete transmission")]
    PartialSend,
    #[error("too few domain name servers (got {0}, need at least 2)")]
    TooFewDns(usize),
    #[error("received packet with wrong client duid (got {0}, want {1})")]
    WrongClientId(String, String),
    #[error("received packet with wrong server duid (got {0}, want {1})")]
    WrongServerId(String, String),

    #[error("parse address: {0}")]
    AddrParse(#[from] net::AddrParseError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("nul: {0}")]
    Nul(#[from] ffi::NulError),
    #[error("system time monotonicity error: {0}")]
    SystemTime(#[from] time::SystemTimeError),

    #[error("can't receive from tokio watch channel: {0}")]
    WatchRecv(#[from] watch::error::RecvError),

    #[error("dhcproto decode: {0}")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("dhcproto encode: {0}")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
