use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A network, that is an IP address and a mask
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// Represent an IPv4 network address
    V4(Ipv4Addr, Ipv4Addr),
    /// Represent an IPv6 network address
    V6(Ipv6Addr, Ipv6Addr),
}

impl fmt::Display for Network {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::V4(address, mask) => write!(fmt, "{}/{}", address, mask),
            Network::V6(address, mask) => write!(fmt, "{}/{}", address, mask),
        }
    }
}

/// Represent an IP address. This type is similar to `std::net::IpAddr` but it supports IPv6 scope
/// identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedIp {
    /// Represent an IPv4 address
    V4(Ipv4Addr),
    /// Represent an IPv6 and its scope identifier, if any
    V6(Ipv6Addr, Option<String>),
}

impl Into<IpAddr> for ScopedIp {
    fn into(self) -> IpAddr {
        match self {
            ScopedIp::V4(ip) => IpAddr::from(ip),
            ScopedIp::V6(ip, _) => IpAddr::from(ip),
        }
    }
}

impl<'a> Into<IpAddr> for &'a ScopedIp {
    fn into(self) -> IpAddr {
        match *self {
            ScopedIp::V4(ref ip) => IpAddr::from(*ip),
            ScopedIp::V6(ref ip, _) => IpAddr::from(*ip),
        }
    }
}

impl From<Ipv6Addr> for ScopedIp {
    fn from(value: Ipv6Addr) -> Self {
        ScopedIp::V6(value, None)
    }
}

impl From<Ipv4Addr> for ScopedIp {
    fn from(value: Ipv4Addr) -> Self {
        ScopedIp::V4(value)
    }
}

impl From<IpAddr> for ScopedIp {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => ScopedIp::from(ip),
            IpAddr::V6(ip) => ScopedIp::from(ip),
        }
    }
}

impl FromStr for ScopedIp {
    type Err = AddrParseError;
    /// Parse a string representing an IP address.
    fn from_str(s: &str) -> Result<ScopedIp, AddrParseError> {
        let mut parts = s.split('%');
        let addr = parts.next().unwrap();
        match IpAddr::from_str(addr) {
            Ok(IpAddr::V4(ip)) => {
                if parts.next().is_some() {
                    // It's not a valid IPv4 address if it contains a '%'
                    Err(AddrParseError)
                } else {
                    Ok(ScopedIp::from(ip))
                }
            }
            Ok(IpAddr::V6(ip)) => if let Some(scope_id) = parts.next() {
                if scope_id.is_empty() {
                    return Err(AddrParseError);
                }
                for c in scope_id.chars() {
                    if !c.is_alphanumeric() {
                        return Err(AddrParseError);
                    }
                }
                Ok(ScopedIp::V6(ip, Some(scope_id.to_string())))
            } else {
                Ok(ScopedIp::V6(ip, None))
            },
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for ScopedIp {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScopedIp::V4(ref address) => address.fmt(fmt),
            ScopedIp::V6(ref address, None) => address.fmt(fmt),
            ScopedIp::V6(ref address, Some(ref scope)) => write!(fmt, "{}%{}", address, scope),
        }
    }
}

/// An error which can be returned when parsing an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("invalid IP address syntax")
    }
}

impl Error for AddrParseError {
}

impl From<::std::net::AddrParseError> for AddrParseError {
    fn from(_: ::std::net::AddrParseError) -> Self {
        AddrParseError
    }
}
