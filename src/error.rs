use std::{ffi, io, net};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no ia_pd")]
    NoIAPD,
    #[error("no ia_pd status code")]
    NoIAPDStatus,
    #[error("no ia_prefix")]
    NoIAPrefix,
    #[error("incomplete transmission")]
    PartialSend,

    #[error("parse address: {0}")]
    AddrParse(#[from] net::AddrParseError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("nul: {0}")]
    Nul(#[from] ffi::NulError),

    #[error("dhcproto decode: {0}")]
    DhcprotoDecode(#[from] dhcproto::error::DecodeError),
    #[error("dhcproto encode: {0}")]
    DhcprotoEncode(#[from] dhcproto::error::EncodeError),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
