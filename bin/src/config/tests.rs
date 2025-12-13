use super::*;

#[cfg(feature = "recursor")]
#[test]
fn example_recursor_config() {
    toml::from_str::<Config>(include_str!(
        "../../../tests/test-data/test_configs/example_recursor.toml"
    ))
    .unwrap();
}

#[cfg(all(feature = "recursor", any(feature = "__tls", feature = "__quic")))]
#[test]
fn example_recursor_opportunistic_enc_config() {
    toml::from_str::<Config>(include_str!(
        "../../../tests/test-data/test_configs/example_recursor_opportunistic_enc.toml"
    ))
    .unwrap();
}

#[cfg(feature = "resolver")]
#[test]
fn single_store_config_error_message() {
    match toml::from_str::<Config>(
        r#"[[zones]]
               zone = "."
               zone_type = "External"

               [zones.stores]
               ype = "forward""#,
    ) {
        Ok(val) => panic!("expected error value; got ok: {val:?}"),
        Err(e) => assert!(e.to_string().contains("missing field `type`")),
    }
}

#[cfg(feature = "resolver")]
#[test]
fn chained_store_config_error_message() {
    match toml::from_str::<Config>(
        r#"[[zones]]
               zone = "."
               zone_type = "External"

               [[zones.stores]]
               type = "forward"

               [[zones.stores.name_servers]]
               ip = "8.8.8.8"
               trust_negative_responses = false
               connections = [
                   { protocol = { type = "udp" } },
               ]

               [[zones.stores]]
               type = "forward"

               [[zones.stores.name_servers]]
               ip = "1.1.1.1"
               trust_negative_responses = false
               connections = [
                   { rotocol = { type = "udp" } },
               ]"#,
    ) {
        Ok(val) => panic!("expected error value; got ok: {val:?}"),
        Err(e) => assert!(e.to_string().contains("unknown field `rotocol`")),
    }
}

#[cfg(feature = "resolver")]
#[test]
fn file_store_zone_path() {
    match toml::from_str::<Config>(
        r#"[[zones]]
               zone = "localhost"
               zone_type = "Primary"

               [zones.stores]
               type = "file"
               zone_path = "default/localhost.zone""#,
    ) {
        Ok(val) => {
            let ZoneTypeConfig::Primary(config) = &val.zones[0].zone_type_config else {
                panic!("expected primary zone type");
            };

            assert_eq!(config.stores.len(), 1);
            assert!(matches!(
                    &config.stores[0],
                ServerStoreConfig::File(FileConfig { zone_path }) if zone_path == Path::new("default/localhost.zone"),
            ));
        }
        Err(e) => panic!("expected successful parse: {e:?}"),
    }
}
