use std::collections::HashMap;

use serde::Deserialize;

use hickory_proto::rr::RecordType;

use super::{TtlBounds, TtlConfig};

#[derive(Deserialize)]
pub(super) struct TtlConfigMap(HashMap<TtlConfigField, TtlBounds>);

impl From<TtlConfigMap> for TtlConfig {
    fn from(value: TtlConfigMap) -> Self {
        let mut default = TtlBounds::default();
        let mut by_query_type = HashMap::new();
        for (field, bounds) in value.0.into_iter() {
            match field {
                TtlConfigField::RecordType(record_type) => {
                    by_query_type.insert(record_type, bounds);
                }
                TtlConfigField::Default => default = bounds,
            }
        }
        Self {
            default,
            by_query_type,
        }
    }
}

#[derive(PartialEq, Eq, Hash, Deserialize)]
enum TtlConfigField {
    #[serde(rename = "default")]
    Default,
    #[serde(untagged)]
    RecordType(RecordType),
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::dns_lru::TtlConfig;

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
            error.message().contains("data did not match any variant"),
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
