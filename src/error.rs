use std::{fmt, io, net, time};

use tokio::sync::watch;

#[derive(Debug)]
pub enum Error {
    LeaseNotFound,
    NoClientId,
    NoDns,
    NoIAPD,
    NoIAPrefix,
    NoServerId,
    PartialSend(usize, usize),
    TooFewDns(usize),
    WrongClientId(String, String),
    WrongServerId(String, String),

    AddrParse(net::AddrParseError),
    Io(io::Error),
    SystemTime(time::SystemTimeError),

    WatchRecv(watch::error::RecvError),

    DhcprotoDecode(dhcproto::error::DecodeError),
    DhcprotoEncode(dhcproto::error::EncodeError),
    SerdeJson(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseNotFound => write!(f, "lease has been obtained but doesn't exist")?,
            Self::NoClientId => write!(f, "server did not include a client id option")?,
            Self::NoDns => write!(f, "server did not include a domain name servers option")?,
            Self::NoIAPD => write!(f, "server did not include an ia_pd option")?,
            Self::NoIAPrefix => write!(
                f,
                "server did not include an ia_prefix option in the ia_pd option"
            )?,
            Self::NoServerId => write!(f, "server did not include a server id option")?,
            Self::PartialSend(want, got) => write!(
                f,
                "unable to send full packet (expected {}, got {})",
                want, got
            )?,
            Self::TooFewDns(n) => write!(
                f,
                "too few domain name servers (expected at least 2, got {})",
                n
            )?,
            Self::WrongClientId(want, got) => write!(
                f,
                "received packet with wrong client duid (expected {}, got {})",
                want, got
            )?,
            Self::WrongServerId(want, got) => write!(
                f,
                "received packet with wrong server duid (expected {}, got {})",
                want, got
            )?,
            Self::AddrParse(e) => write!(f, "can't parse network address: {}", e)?,
            Self::Io(e) => write!(f, "io error: {}", e)?,
            Self::SystemTime(e) => write!(f, "system time monotonicity error: {}", e)?,
            Self::WatchRecv(e) => write!(f, "can't receive from tokio watch channel: {}", e)?,
            Self::DhcprotoDecode(e) => write!(f, "dhcproto decode error: {}", e)?,
            Self::DhcprotoEncode(e) => write!(f, "dhcproto encode error: {}", e)?,
            Self::SerdeJson(e) => write!(f, "serde_json error: {}", e)?,
        }

        Ok(())
    }
}

impl From<net::AddrParseError> for Error {
    fn from(e: net::AddrParseError) -> Error {
        Error::AddrParse(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<time::SystemTimeError> for Error {
    fn from(e: time::SystemTimeError) -> Error {
        Error::SystemTime(e)
    }
}

impl From<watch::error::RecvError> for Error {
    fn from(e: watch::error::RecvError) -> Error {
        Error::WatchRecv(e)
    }
}

impl From<dhcproto::error::DecodeError> for Error {
    fn from(e: dhcproto::error::DecodeError) -> Error {
        Error::DhcprotoDecode(e)
    }
}

impl From<dhcproto::error::EncodeError> for Error {
    fn from(e: dhcproto::error::EncodeError) -> Error {
        Error::DhcprotoEncode(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
