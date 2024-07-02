use crate::{container::Container, record::DS, FQDN};

use super::{ZoneFile, DNSKEY};

/// Enum to hold all supported key gen algorithms.
pub(crate) enum KeyAlgorithm {
    RSASHA256,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyAlgorithm::RSASHA256 => "RSASHA256",
        };
        write!(f, "{}", s)
    }
}

pub(crate) struct Signer {
    signed_files: Vec<String>,
    zone: FQDN,
}

const ZONES_DIR: &str = "/etc/zones";
const ZONE_FILENAME: &str = "main.zone";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}

impl Signer {
    /// Sets up signing process for the given [`ZoneFile`]. It's copied into the default location
    /// of the [`Container`].
    ///
    /// The Signer keeps a list of all signed keys & the zone origin.
    pub fn copy_zone_file(container: &Container, zone_file: &ZoneFile) -> crate::Result<Self> {
        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        let zone_file_path = zone_file_path();
        container.cp(&zone_file_path, &zone_file.to_string())?;

        let zone = zone_file.origin().clone();

        Ok(Self {
            signed_files: Vec::new(),
            zone,
        })
    }

    /// Generates a new ZSK with given bits and algorithm.
    pub(crate) fn gen_zsk_key(
        &mut self,
        container: &Container,
        bits: usize,
        algorithm: KeyAlgorithm,
    ) -> crate::Result<DNSKEY> {
        let zone = &self.zone;

        let keygen_cmd = format!("cd {ZONES_DIR} && ldns-keygen -a {algorithm} -b {bits} {zone}");
        self.gen_key(container, &keygen_cmd)
    }

    /// Generates a new KSK with given bits and algorithm.
    pub(crate) fn gen_ksk_key(
        &mut self,
        container: &Container,
        bits: usize,
        algorithm: KeyAlgorithm,
    ) -> crate::Result<DNSKEY> {
        let zone = &self.zone;

        let keygen_cmd =
            format!("cd {ZONES_DIR} && ldns-keygen -k -a {algorithm} -b {bits} {zone}");
        self.gen_key(container, &keygen_cmd)
    }

    /// Generates a new signed key
    ///
    /// The keygen commands differs between KSK & ZSK versions.
    fn gen_key(&mut self, container: &Container, command: &str) -> crate::Result<DNSKEY> {
        let key_filename = container.stdout(&["sh", "-c", &command])?;
        let key_path = format!("{ZONES_DIR}/{key_filename}.key");
        let signed_key: DNSKEY = container.stdout(&["cat", &key_path])?.parse()?;

        self.signed_files.push(key_filename);

        Ok(signed_key)
    }

    /// Generates the signed [`ZoneFile`] & [`DS`] record from the list of previously generated signed keys.
    pub(crate) fn sign(&mut self, container: &Container) -> crate::Result<(ZoneFile, DS)> {
        let zone_file_path = zone_file_path();

        let key_filenames = self.signed_files.clone().join(" ");

        // -n = use NSEC3 instead of NSEC
        // -p = set the opt-out flag on all nsec3 rrs
        let signzone =
            format!("cd {ZONES_DIR} && ldns-signzone -n -p {ZONE_FILENAME} {key_filenames}");
        container.status_ok(&["sh", "-c", &signzone])?;

        // TODO do we want to make the hashing algorithm configurable?
        // -2 = use SHA256 for the DS hash
        let key2ds = format!("cd {ZONES_DIR} && ldns-key2ds -n -2 {ZONE_FILENAME}.signed");
        let output = container.stdout(&["sh", "-c", &key2ds])?;
        let ds: DS = output.parse()?;

        let signed: ZoneFile = container
            .stdout(&["cat", &format!("{zone_file_path}.signed")])?
            .parse()?;

        Ok((signed, ds))
    }
}
