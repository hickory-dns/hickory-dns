use std::collections::hash_map::Entry;

use serde::{
    de::{value::StrDeserializer, Error, MapAccess, Visitor},
    Deserialize,
};

use hickory_proto::rr::RecordType;

use super::TtlConfig;

const TTL_CONFIG_FIELDS: [&str; 37] = [
    "default",
    "A",
    "AAAA",
    "ANAME",
    "ANY",
    "AXFR",
    "CAA",
    "CDS",
    "CDNSKEY",
    "CERT",
    "CNAME",
    "CSYNC",
    "DNSKEY",
    "DS",
    "HINFO",
    "HTTPS",
    "IXFR",
    "KEY",
    "MX",
    "NAPTR",
    "NS",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "NULL",
    "OPENPGPKEY",
    "OPT",
    "PTR",
    "RRSIG",
    "SIG",
    "SOA",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TSIG",
    "TXT",
];

// This is implemented manually in order to leverage the existing deserialization code for
// `RecordType`.
//
// A derived implementation cannot be used without requiring an extra level of TOML tables, because
// `#[serde(flatten)]` and `#[serde(deny_unknown_fields)]` are incompatible.
impl<'de> Deserialize<'de> for TtlConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("TtlConfig", &TTL_CONFIG_FIELDS, TtlConfigVisitor)
    }
}

struct TtlConfigVisitor;

impl<'de> Visitor<'de> for TtlConfigVisitor {
    type Value = TtlConfig;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("struct TtlConfig")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut policy = TtlConfig::default();
        let mut seen_default = false;
        while let Some(key) = map.next_key()? {
            match key {
                TtlConfigField::RecordType(record_type) => {
                    match policy.by_query_type.entry(record_type) {
                        Entry::Occupied(_) => {
                            return Err(Error::duplicate_field(record_type.into()));
                        }
                        Entry::Vacant(vacant_entry) => {
                            vacant_entry.insert(map.next_value()?);
                        }
                    }
                }
                TtlConfigField::Default => {
                    if seen_default {
                        return Err(Error::duplicate_field("default"));
                    }
                    policy.default = map.next_value()?;
                    seen_default = true;
                }
            }
        }
        Ok(policy)
    }
}

enum TtlConfigField {
    RecordType(RecordType),
    Default,
}

impl<'de> Deserialize<'de> for TtlConfigField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(TtlConfigFieldVisitor)
    }
}

struct TtlConfigFieldVisitor;

impl<'de> Visitor<'de> for TtlConfigFieldVisitor {
    type Value = TtlConfigField;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("record type or `default`")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if v == "default" {
            Ok(TtlConfigField::Default)
        } else {
            Ok(TtlConfigField::RecordType(
                RecordType::deserialize(StrDeserializer::new(v))
                    .map_err(|_: E| Error::unknown_field(v, &TTL_CONFIG_FIELDS))?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fmt::Display};

    use hickory_proto::rr::RecordType;
    use serde::{
        de::{DeserializeSeed, EnumAccess, Error, VariantAccess, Visitor},
        Deserialize, Deserializer,
    };

    use super::{TtlConfig, TTL_CONFIG_FIELDS};

    /// Check the fields array used by this `Deserialize` implementation against the variants array
    /// of the automatically-generated `Deserialize` implementation for [`RecordType`].
    ///
    /// If this test is failing after adding a new variant to `RecordType`, add its name to
    /// [`CACHE_POLICY_FIELDS`] above.
    #[test]
    fn check_fields_array() {
        /// This deserializer just exists to intercept the variants array produced by the derived
        /// `Deserialize` implementation of `RecordType`, in order to check for drift between it
        /// and [`CACHE_POLICY_FIELDS`].
        #[derive(Clone, Copy)]
        struct TestDeserializer;

        impl<'de> Deserializer<'de> for TestDeserializer {
            type Error = TestError;

            fn deserialize_enum<V>(
                self,
                name: &'static str,
                variants: &'static [&'static str],
                visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                assert_eq!(name, "RecordType");

                let mut record_types = variants.iter().collect::<HashSet<_>>();
                // Clean up two variants that were intentionally excluded.
                assert!(record_types.remove(&"Unknown"));
                assert!(record_types.remove(&"ZERO"));

                let mut fields = TTL_CONFIG_FIELDS.iter().collect::<HashSet<_>>();
                assert_eq!(
                    TTL_CONFIG_FIELDS.len(),
                    fields.len(),
                    "duplicate in CACHE_POLICY_FIELDS"
                );
                // Clean up the added default field.
                assert!(fields.remove(&"default"));

                // Check that the list of per-record fields matches the relevant variants of
                // `RecordType`.
                assert_eq!(record_types, fields);

                visitor.visit_enum(self)
            }

            fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                // Feed a string literal to the visitor (in lieu of reading from deserializer
                // input).
                visitor.visit_str("A")
            }

            // All other required methods are not needed by this test, so they just panic.

            fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_bool<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_i32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_i64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_u8<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_u32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_u64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_unit_struct<V>(
                self,
                _name: &'static str,
                _visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_newtype_struct<V>(
                self,
                _name: &'static str,
                _visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_tuple_struct<V>(
                self,
                _name: &'static str,
                _len: usize,
                _visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_struct<V>(
                self,
                _name: &'static str,
                _fields: &'static [&'static str],
                _visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }
        }

        impl<'de> EnumAccess<'de> for TestDeserializer {
            type Error = TestError;

            type Variant = Self;

            fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
            where
                V: DeserializeSeed<'de>,
            {
                let val = seed.deserialize(self)?;
                Ok((val, self))
            }
        }

        impl<'de> VariantAccess<'de> for TestDeserializer {
            type Error = TestError;

            fn unit_variant(self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value, Self::Error>
            where
                T: DeserializeSeed<'de>,
            {
                panic!("unused")
            }

            fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }

            fn struct_variant<V>(
                self,
                _fields: &'static [&'static str],
                _visitor: V,
            ) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                panic!("unused")
            }
        }

        #[derive(Debug)]
        struct TestError(String);

        impl Display for TestError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::error::Error for TestError {}

        impl Error for TestError {
            fn custom<T>(msg: T) -> Self
            where
                T: Display,
            {
                Self(msg.to_string())
            }
        }

        // Invoke the deserialize implementation with our deserializer.
        assert_eq!(
            RecordType::deserialize(TestDeserializer).unwrap(),
            RecordType::A
        );
    }

    #[test]
    fn error_cases() {
        // Duplicate of "default"
        let input = r#"[default]
positive_max_ttl = 3600
[default]
positive_max_ttl = 3599"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error.message().contains("duplicate key `default`"),
            "wrong error message: {error}"
        );

        // Duplicate of a record type
        let input = r#"[default]
positive_max_ttl = 86400
[OPENPGPKEY]
positive_max_ttl = 3600
[OPENPGPKEY]
negative_min_ttl = 60"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error.message().contains("duplicate key `OPENPGPKEY`"),
            "wrong error message: {error}"
        );

        // Neither "default" nor a record type
        let input = r#"[not_a_record_type]
positive_max_ttl = 3600"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error
                .message()
                .contains("unknown field `not_a_record_type`"),
            "wrong error message: {error}"
        );

        // Array instead of table
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[allow(unused)]
            cache_policy: TtlConfig,
        }
        let input = r#"cache_policy = []"#;
        let error = toml::from_str::<Wrapper>(input).unwrap_err();
        assert!(
            error.message().contains("invalid type: sequence"),
            "wrong error message: {error}"
        );

        // String instead of table
        let input = r#"cache_policy = "yes""#;
        let error = toml::from_str::<Wrapper>(input).unwrap_err();
        assert!(
            error.message().contains("invalid type: string"),
            "wrong error message: {error}"
        );
    }
}
