use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    FQDN,
    container::Container,
    name_server::{DS2, Signed},
    record::DS,
};

use super::{DNSKEY, Keypair, SigningKeys, ZoneFile};

const KEYS_DIR: &str = "/tmp/keys";
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
    implementation: Implementation,
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
            implementation: Implementation::default(),
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
            implementation: Implementation::default(),
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
            implementation: Implementation::default(),
        }
    }

    pub fn rsasha256_nsec3_optout() -> Self {
        Self {
            algorithm: Algorithm::RSASHA256,
            // 2048-bit SHA256 matches `$ dig DNSKEY .` in length
            zsk_bits: 2_048,
            ksk_bits: 2_048,
            expiration: None,
            inception: None,
            nsec: Nsec::_3 {
                salt: None,
                opt_out: true,
            },
            implementation: Implementation::Bindutils,
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
            implementation: Implementation::default(),
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
    _3 { opt_out: bool, salt: Option<String> },
}

impl Default for Nsec {
    fn default() -> Self {
        Self::_3 {
            opt_out: false,
            salt: None,
        }
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

#[derive(Debug, Default, Clone, Copy)]
enum Implementation {
    #[default]
    Ldns,
    Bindutils,
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

    /// Generates ZSK and KSK keys.
    pub fn generate_keys(&self, zone: &FQDN) -> crate::Result<SigningKeys> {
        self.container.status_ok(&["mkdir", "-p", KEYS_DIR])?;
        let zsk = self.gen_zsk_key(zone)?;
        let ksk = self.gen_ksk_key(zone, zsk.public.rdata.calculate_key_tag())?;
        Ok(SigningKeys { ksk, zsk })
    }

    /// Signs the [`ZoneFile`] with the [`SignSettings`].
    pub fn sign_zone(&self, zone_file: &ZoneFile, keys: &SigningKeys) -> crate::Result<Signed> {
        self.container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        let zone_file_path = zone_file_path();
        self.container.cp(&zone_file_path, &zone_file.to_string())?;

        let zone = zone_file.origin();
        // inherit SOA's TTL value
        let ttl = zone_file.soa.ttl;

        let zsk_filename = "zsk".to_owned();
        let ksk_filename = "ksk".to_owned();
        self.container.cp(
            &format!("{ZONES_DIR}/{zsk_filename}.key"),
            &format!("{}\n", keys.zsk.public),
        )?;
        self.container.cp(
            &format!("{ZONES_DIR}/{zsk_filename}.private"),
            &format!("{}\n", keys.zsk.private),
        )?;
        self.container.cp(
            &format!("{ZONES_DIR}/{ksk_filename}.key"),
            &format!("{}\n", keys.ksk.public),
        )?;
        self.container.cp(
            &format!("{ZONES_DIR}/{ksk_filename}.private"),
            &format!("{}\n", keys.ksk.private),
        )?;

        let signzone_cmd = self.sign_zone_cmd(zone, [zsk_filename, ksk_filename].iter().cloned());
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
        let ds = DS2::classify(dses, &keys.zsk.public, &keys.ksk.public);

        let signed: ZoneFile = self
            .container
            .stdout(&["cat", &format!("{zone_file_path}.signed")])?
            .parse()?;

        let ksk = keys.ksk.public.clone().with_ttl(ttl);
        let zsk = keys.zsk.public.clone().with_ttl(ttl);

        Ok(Signed {
            ds,
            signed,
            ksk,
            zsk,
            use_dnssec: true,
        })
    }

    fn gen_zsk_key(&self, zone: &FQDN) -> crate::Result<Keypair> {
        self.gen_key(&ldns_keygen_zsk(&self.settings, zone))
    }

    fn gen_ksk_key(&self, zone: &FQDN, zsk_keytag: u16) -> crate::Result<Keypair> {
        // ldns-signzone will not accept a KSK that has either the same
        // keytag as the ZSK, or a keytag one higher than the ZSK.
        // See https://github.com/hickory-dns/hickory-dns/issues/2555
        for _ in 0..100 {
            let keypair = self.gen_key(&ldns_keygen_ksk(&self.settings, zone))?;
            let ksk_keytag = keypair.public.rdata.calculate_key_tag();
            if ksk_keytag != zsk_keytag && ksk_keytag != zsk_keytag.wrapping_add(1) {
                return Ok(keypair);
            }
        }

        Err(
            format!("could not generate collision-free KSK for ZSK with keytag {zsk_keytag}")
                .into(),
        )
    }

    fn gen_key(&self, command: &str) -> crate::Result<Keypair> {
        let command = format!("cd {KEYS_DIR} && {command}");
        let key_filename = self.container.stdout(&["sh", "-c", &command])?;
        let key_path = format!("{KEYS_DIR}/{key_filename}.key");
        let public_key: DNSKEY = self.container.stdout(&["cat", &key_path])?.parse()?;
        let private_path = format!("{KEYS_DIR}/{key_filename}.private");
        let private_key = self.container.stdout(&["cat", &private_path])?;

        Ok(Keypair {
            public: public_key,
            private: private_key,
        })
    }

    fn sign_zone_cmd<T>(&self, zone: &FQDN, keys: T) -> String
    where
        T: Iterator<Item = String>,
    {
        match self.settings.implementation {
            Implementation::Ldns => {
                let mut args = vec![String::from("ldns-signzone"), "-A".to_string()];

                if let Some(expiration) = self.settings.expiration {
                    args.push(format!("-e {}", expiration));
                }
                if let Some(inception) = self.settings.inception {
                    args.push(format!("-i {}", inception));
                }

                // NSEC3 related options
                // -n = use NSEC3 instead of NSEC
                if let Nsec::_3 { salt, opt_out } = &self.settings.nsec {
                    args.push("-n".to_string());

                    if *opt_out {
                        args.push("-p".to_string());
                    }

                    if let Some(salt) = salt {
                        args.push(format!("-s {}", salt));
                    }
                }
                args.push(ZONE_FILENAME.to_string());

                args.extend(keys);
                args.join(" ")
            }
            Implementation::Bindutils => {
                let mut args = vec!["dnssec-signzone".to_string()];

                // This will include record names for all records and use compact record
                // formats, which the dns-test record parsing code needs.
                args.push("-O full".to_string());

                if let Some(expiration) = self.settings.expiration {
                    args.push(format!("-e {}", expiration));
                }
                if let Some(inception) = self.settings.inception {
                    args.push(format!("-s {}", inception));
                }

                // Set -3 for NSEC3, optionally followed by a salt.
                // -A sets opt-out
                if let Nsec::_3 { salt, opt_out } = &self.settings.nsec {
                    args.push("-3".to_string());

                    if let Some(salt) = salt {
                        args.push(salt.to_string());
                    } else {
                        // Set no salt, or else dnssec-signzone will interepret the next
                        // argument as a salt.
                        args.push("''".to_string());
                    }

                    if *opt_out {
                        args.push("-A".to_string());
                    }
                }

                // We must pass dnssec-signzone the origin of the zone, and specify
                // -S to include the DNSKEY records for the keys passed in on the CLI.
                args.push(format!("-o {zone}"));
                args.push("-S".to_string());

                args.push(ZONE_FILENAME.to_string());

                args.extend(keys);
                args.join(" ")
            }
        }
    }
}
