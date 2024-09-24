use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    container::Container,
    name_server::{Signed, DS2},
    record::DS,
    FQDN,
};

use super::{ZoneFile, DNSKEY};

const ZONES_DIR: &str = "/etc/zones";
const ZONE_FILENAME: &str = "main.zone";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}

#[derive(Clone)]
pub struct SignSettings {
    zsk_bits: u16,
    ksk_bits: u16,
    algorithm: Algorithm,
    expiration: Option<u64>,
    inception: Option<u64>,
    nsec: Nsec,
}

impl SignSettings {
    pub fn rsasha1_nsec3() -> Self {
        Self {
            algorithm: Algorithm::RSASHA1_NSEC3,
            zsk_bits: 1_024,
            ksk_bits: 2_048,
            expiration: None,
            inception: None,
            nsec: Nsec::default(),
        }
    }

    pub fn dsa() -> Self {
        Self {
            algorithm: Algorithm::DSA,
            zsk_bits: 1_024,
            ksk_bits: 1_024,
            expiration: None,
            inception: None,
            nsec: Nsec::default(),
        }
    }

    pub fn rsamd5() -> Self {
        Self {
            algorithm: Algorithm::RSAMD5,
            zsk_bits: 2_048,
            ksk_bits: 2_048,
            expiration: None,
            inception: None,
            nsec: Nsec::default(),
        }
    }

    fn rsasha256() -> Self {
        Self {
            algorithm: Algorithm::RSASHA256,
            // 2048-bit SHA256 matches `$ dig DNSKEY .` in length
            zsk_bits: 2_048,
            ksk_bits: 2_048,
            expiration: None,
            inception: None,
            nsec: Nsec::default(),
        }
    }

    /// Set the expiration parameter from a `u64`.
    pub fn expiration_from_u64(mut self, timestamp: u64) -> Self {
        self.expiration = Some(timestamp);
        self
    }

    /// Set the expiration parameter.
    pub fn expiration(mut self, expiraton: SystemTime) -> Self {
        self.expiration = Some(unix_timestamp(&expiraton));
        self
    }

    /// Set the inception parameter.
    pub fn inception(mut self, inception: SystemTime) -> Self {
        self.inception = Some(unix_timestamp(&inception));
        self
    }

    /// Changes the NSEC policy (default is NSEC3; see `Nsec::default`)
    pub fn nsec(mut self, nsec: Nsec) -> Self {
        self.nsec = nsec;
        self
    }
}

impl Default for SignSettings {
    fn default() -> Self {
        Self::rsasha256()
    }
}

#[derive(Clone)]
pub enum Nsec {
    _1,
    _3 { salt: Option<String> },
}

impl Default for Nsec {
    fn default() -> Self {
        Self::_3 { salt: None }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
enum Algorithm {
    DSA,
    RSAMD5,
    RSASHA1_NSEC3,
    RSASHA256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Generates the command string to generate ZSK using `ldns-keygen`
pub fn ldns_keygen_zsk(settings: &SignSettings, zone: &FQDN) -> String {
    format!(
        "ldns-keygen -a {} -b {} {}",
        settings.algorithm, settings.zsk_bits, zone
    )
}

/// Generates the command string to generate KSK using `ldns-keygen`
pub fn ldns_keygen_ksk(settings: &SignSettings, zone: &FQDN) -> String {
    format!(
        "ldns-keygen -k -a {} -b {} {}",
        settings.algorithm, settings.ksk_bits, zone
    )
}

fn unix_timestamp(system_time: &SystemTime) -> u64 {
    system_time
        .duration_since(UNIX_EPOCH)
        .expect("Failed to get timestamp")
        .as_secs()
}

pub struct Signer<'a> {
    /// Actions to generate keys and sign zone files are applied to this Container.
    container: &'a Container,
    /// Settings to sign with.
    settings: SignSettings,
}

impl<'a> Signer<'a> {
    pub fn new(container: &'a Container, settings: SignSettings) -> crate::Result<Self> {
        Ok(Self {
            container,
            settings,
        })
    }

    /// Signs the [`ZoneFile`], first Generates ZSK & KSK keys, then signs the zone file with the [`SignSettings`].
    pub fn sign_zone(&self, zone_file: &ZoneFile) -> crate::Result<Signed> {
        self.container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        let zone_file_path = zone_file_path();
        self.container.cp(&zone_file_path, &zone_file.to_string())?;

        let zone = zone_file.origin();
        // inherit SOA's TTL value
        let ttl = zone_file.soa.ttl;

        let (zsk, zsk_filename) = self.gen_zsk_key(zone)?;
        let (ksk, ksk_filename) = self.gen_ksk_key(zone)?;

        let signzone_cmd = self.sign_zone_cmd([zsk_filename, ksk_filename].iter().cloned());
        let signzone = format!("cd {ZONES_DIR} && {}", signzone_cmd);
        self.container.status_ok(&["sh", "-c", &signzone])?;

        // TODO do we want to make the hashing algorithm configurable?
        // -2 = use SHA256 for the DS hash
        let key2ds = format!("cd {ZONES_DIR} && ldns-key2ds -f -n -2 {ZONE_FILENAME}.signed");
        let dses = self
            .container
            .stdout(&["sh", "-c", &key2ds])?
            .lines()
            .map(|line| line.parse())
            .collect::<Result<Vec<DS>, _>>()?;
        let ds = DS2::classify(dses, &zsk, &ksk);

        let signed: ZoneFile = self
            .container
            .stdout(&["cat", &format!("{zone_file_path}.signed")])?
            .parse()?;

        let ksk = ksk.with_ttl(ttl);
        let zsk = zsk.with_ttl(ttl);

        Ok(Signed {
            ds,
            signed,
            ksk,
            zsk,
            use_dnssec: true,
        })
    }

    fn gen_zsk_key(&self, zone: &FQDN) -> crate::Result<(DNSKEY, String)> {
        self.gen_key(&ldns_keygen_zsk(&self.settings, zone))
    }

    fn gen_ksk_key(&self, zone: &FQDN) -> crate::Result<(DNSKEY, String)> {
        self.gen_key(&ldns_keygen_ksk(&self.settings, zone))
    }

    fn gen_key(&self, command: &str) -> crate::Result<(DNSKEY, String)> {
        let command = format!("cd {ZONES_DIR} && {command}");
        let key_filename = self.container.stdout(&["sh", "-c", &command])?;
        let key_path = format!("{ZONES_DIR}/{key_filename}.key");
        let signed_key: DNSKEY = self.container.stdout(&["cat", &key_path])?.parse()?;

        Ok((signed_key, key_filename))
    }

    fn sign_zone_cmd<T>(&self, keys: T) -> String
    where
        T: Iterator<Item = String>,
    {
        let mut args = vec![String::from("ldns-signzone"), "-A".to_string()];

        if let Some(expiration) = self.settings.expiration {
            args.push(format!("-e {}", expiration));
        }
        if let Some(inception) = self.settings.inception {
            args.push(format!("-i {}", inception));
        }

        // NSEC3 related options
        // -n = use NSEC3 instead of NSEC
        if let Nsec::_3 { salt } = &self.settings.nsec {
            args.push("-n".to_string());

            if let Some(salt) = salt {
                args.push(format!("-s {}", salt));
            }
        }
        args.push(ZONE_FILENAME.to_string());

        args.extend(keys);
        args.join(" ")
    }
}
