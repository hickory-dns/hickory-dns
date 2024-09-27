use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{Utf8Error, from_utf8};

use {AddrParseError, Config, Network, Lookup, Family};

quick_error!{
    /// Error while parsing resolv.conf file
    #[derive(Debug)]
    pub enum ParseError {
        /// Error that may be returned when the string to parse contains invalid UTF-8 sequences
        InvalidUtf8(line: usize, err: Utf8Error) {
            display("bad unicode at line {}: {}", line, err)
            source(err)
        }
        /// Error returned a value for a given directive is invalid.
        /// This can also happen when the value is missing, if the directive requires a value.
        InvalidValue(line: usize) {
            display("directive at line {} is improperly formatted \
                or contains invalid value", line)
        }
        /// Error returned when a value for a given option is invalid.
        /// This can also happen when the value is missing, if the option requires a value.
        InvalidOptionValue(line: usize) {
            display("directive options at line {} contains invalid \
                value of some option", line)
        }
        /// Error returned when a invalid option is found.
        InvalidOption(line: usize) {
            display("option at line {} is not recognized", line)
        }
        /// Error returned when a invalid directive is found.
        InvalidDirective(line: usize) {
            display("directive at line {} is not recognized", line)
        }
        /// Error returned when a value cannot be parsed an an IP address.
        InvalidIp(line: usize, err: AddrParseError) {
            display("directive at line {} contains invalid IP: {}", line, err)
        }
        /// Error returned when there is extra data at the end of a line.
        ExtraData(line: usize) {
            display("extra data at the end of the line {}", line)
        }
    }
}

fn ip_v4_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip: Ipv4Addr = pair.next().unwrap().parse()?;
    if ip.is_unspecified() {
        return Err(AddrParseError);
    }
    if let Some(mask) = pair.next() {
        let mask = mask.parse()?;
        // make sure this is a valid mask
        let value: u32 = ip.octets().iter().fold(0, |acc, &x| acc + u32::from(x));
        if value == 0 || (value & !value != 0) {
            Err(AddrParseError)
        } else {
            Ok(Network::V4(ip, mask))
        }
    } else {
        // We have to "guess" the mask.
        //
        // FIXME(@little-dude) right now, we look at the number or bytes that are 0, but maybe we
        // should use the number of bits that are 0.
        //
        // In other words, with this implementation, the mask of `128.192.0.0` will be
        // `255.255.0.0` (a.k.a `/16`). But we could also consider that the mask is `/10` (a.k.a
        // `255.63.0.0`).
        //
        // My only source on topic is the "DNS and Bind" book which suggests using bytes, not bits.
        let octets = ip.octets();
        let mask = if octets[3] == 0 {
            if octets[2] == 0 {
                if octets[1] == 0 {
                    Ipv4Addr::new(255, 0, 0, 0)
                } else {
                    Ipv4Addr::new(255, 255, 0, 0)
                }
            } else {
                Ipv4Addr::new(255, 255, 255, 0)
            }
        } else {
            Ipv4Addr::new(255, 255, 255, 255)
        };
        Ok(Network::V4(ip, mask))
    }
}

fn ip_v6_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip = pair.next().unwrap().parse()?;
    if let Some(msk) = pair.next() {
        // FIXME: validate the mask
        Ok(Network::V6(ip, msk.parse()?))
    } else {
        // FIXME: "guess" an appropriate mask for the IP
        Ok(Network::V6(
            ip,
            Ipv6Addr::new(
                65_535,
                65_535,
                65_535,
                65_535,
                65_535,
                65_535,
                65_535,
                65_535,
            ),
        ))
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Config, ParseError> {
    use self::ParseError::*;
    let mut cfg = Config::new();
    'lines: for (lineno, line) in bytes.split(|&x| x == b'\n').enumerate() {
        for &c in line.iter() {
            if c != b'\t' && c != b' ' {
                if c == b';' || c == b'#' {
                    continue 'lines;
                } else {
                    break;
                }
            }
        }
        // All that dances above to allow invalid utf-8 inside the comments
        let mut words = from_utf8(line)
            .map_err(|e| InvalidUtf8(lineno, e))?
            // ignore everything after ';' or '#'
            .split(|c| c == ';' || c == '#')
            .next()
            .ok_or_else(|| InvalidValue(lineno))?
            .split_whitespace();
        let keyword = match words.next() {
            Some(x) => x,
            None => continue,
        };
        match keyword {
            "nameserver" => {
                let srv = words
                    .next()
                    .ok_or_else(|| InvalidValue(lineno))
                    .map(|addr| addr.parse().map_err(|e| InvalidIp(lineno, e)))??;
                cfg.nameservers.push(srv);
                if words.next().is_some() {
                    return Err(ExtraData(lineno));
                }
            }
            "domain" => {
                let dom = words
                    .next()
                    .and_then(|x| x.parse().ok())
                    .ok_or_else(|| InvalidValue(lineno))?;
                cfg.set_domain(dom);
                if words.next().is_some() {
                    return Err(ExtraData(lineno));
                }
            }
            "search" => {
                cfg.set_search(words.map(|x| x.to_string()).collect());
            }
            "sortlist" => {
                cfg.sortlist.clear();
                for pair in words {
                    let netw = ip_v4_netw(pair)
                        .or_else(|_| ip_v6_netw(pair))
                        .map_err(|e| InvalidIp(lineno, e))?;
                    cfg.sortlist.push(netw);
                }
            }
            "options" => {
                for pair in words {
                    let mut iter = pair.splitn(2, ':');
                    let key = iter.next().unwrap();
                    let value = iter.next();
                    if iter.next().is_some() {
                        return Err(ExtraData(lineno));
                    }
                    match (key, value) {
                        // TODO(tailhook) ensure that values are None?
                        ("debug", _) => cfg.debug = true,
                        ("ndots", Some(x)) => {
                            cfg.ndots = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("timeout", Some(x)) => {
                            cfg.timeout = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("attempts", Some(x)) => {
                            cfg.attempts = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("rotate", _) => cfg.rotate = true,
                        ("no-check-names", _) => cfg.no_check_names = true,
                        ("inet6", _) => cfg.inet6 = true,
                        ("ip6-bytestring", _) => cfg.ip6_bytestring = true,
                        ("ip6-dotint", _) => cfg.ip6_dotint = true,
                        ("no-ip6-dotint", _) => cfg.ip6_dotint = false,
                        ("edns0", _) => cfg.edns0 = true,
                        ("single-request", _) => cfg.single_request = true,
                        ("single-request-reopen", _) => cfg.single_request_reopen = true,
                        ("no-reload", _) => cfg.no_reload = true,
                        ("trust-ad", _) => cfg.trust_ad = true,
                        ("no-tld-query", _) => cfg.no_tld_query = true,
                        ("use-vc", _) => cfg.use_vc = true,
                        _ => return Err(InvalidOption(lineno)),
                    }
                }
            }
            "lookup" => {
                for word in words {
                    match word {
                        "file" => cfg.lookup.push(Lookup::File),
                        "bind" => cfg.lookup.push(Lookup::Bind),
                        extra => cfg.lookup.push(Lookup::Extra(extra.to_string())),
                    }
                }
            }
            "family" => {
                for word in words {
                    match word {
                        "inet4" => cfg.family.push(Family::Inet4),
                        "inet6" => cfg.family.push(Family::Inet6),
                        _ => return Err(InvalidValue(lineno)),
                    }
                }
            }
            _ => return Err(InvalidDirective(lineno)),
        }
    }
    Ok(cfg)
}
