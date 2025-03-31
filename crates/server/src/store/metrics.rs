use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};

pub(super) struct StoreMetrics {
    pub(crate) query: QueryStoreMetrics,
    pub(crate) persistent: PersistentStoreMetrics,
}

impl StoreMetrics {
    pub(super) fn new(store: &'static str) -> Self {
        Self {
            query: QueryStoreMetrics::new(store),
            persistent: PersistentStoreMetrics::new(store),
        }
    }
}

pub(super) struct PersistentStoreMetrics {
    pub(super) zone_records_total: Gauge,
    #[cfg(feature = "__dnssec")]
    pub(super) zone_records_dynamically_updated: Counter,
}

impl PersistentStoreMetrics {
    pub(crate) fn new(store: &'static str) -> Self {
        let zone_records_total = gauge!("hickory_zone_records_total", "store" => store);
        describe_gauge!(
            "hickory_zone_records_total",
            Unit::Count,
            "number of dns zone records in persisted storages"
        );

        #[cfg(feature = "__dnssec")]
        let zone_records_dynamically_updated = {
            let zone_records_dynamically_updated =
                counter!("hickory_zone_records_dynamically_updated_total", "store" => store);
            describe_counter!(
                "hickory_zone_records_dynamically_updated_total",
                Unit::Count,
                "number of dns zone records that had been dynamically updated"
            );
            zone_records_dynamically_updated
        };

        Self {
            zone_records_total,
            #[cfg(feature = "__dnssec")]
            zone_records_dynamically_updated,
        }
    }
}

pub(super) struct QueryStoreMetrics {
    pub(super) zone_record_lookups: Counter,
}

impl QueryStoreMetrics {
    pub(crate) fn new(store: &'static str) -> Self {
        let zone_record_lookups = counter!("hickory_zone_record_lookups_total", "store" => store);
        describe_counter!(
            "hickory_zone_record_lookups_total",
            Unit::Count,
            "number of occurred dns zone record lookups"
        );

        Self {
            zone_record_lookups,
        }
    }
}
