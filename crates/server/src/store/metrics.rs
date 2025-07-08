#[cfg(feature = "__dnssec")]
use metrics::{Counter, counter, describe_counter};

use metrics::{Gauge, Unit, describe_gauge, gauge};

pub(super) struct PersistentStoreMetrics {
    pub(super) zone_records: Gauge,
    #[cfg(feature = "__dnssec")]
    pub(super) zone_records_added: Counter,
    #[cfg(feature = "__dnssec")]
    pub(super) zone_records_deleted: Counter,
    #[cfg(feature = "__dnssec")]
    pub(super) zone_records_updated: Counter,
}

impl PersistentStoreMetrics {
    pub(super) fn new(store: &'static str) -> Self {
        let store_key = "store";

        let zone_records_name = "hickory_zone_records_total";
        let zone_records = gauge!(zone_records_name, store_key => store);
        describe_gauge!(
            zone_records_name,
            Unit::Count,
            "number of dns zone records in persisted storages"
        );

        #[cfg(feature = "__dnssec")]
        let (zone_records_added, zone_records_deleted, zone_records_updated) = {
            let zone_records_modified_name = "hickory_zone_records_modified_total";

            let operation_key = "operation";

            let records_added =
                counter!(zone_records_modified_name, store_key => store, operation_key => "added");
            let records_deleted = counter!(zone_records_modified_name, store_key => store, operation_key => "deleted");
            let records_updated = counter!(zone_records_modified_name, store_key => store, operation_key => "updated");

            describe_counter!(
                zone_records_modified_name,
                Unit::Count,
                "number of dns zone records that had been modified"
            );

            (records_added, records_deleted, records_updated)
        };

        Self {
            zone_records,
            #[cfg(feature = "__dnssec")]
            zone_records_added,
            #[cfg(feature = "__dnssec")]
            zone_records_deleted,
            #[cfg(feature = "__dnssec")]
            zone_records_updated,
        }
    }

    #[cfg(feature = "__dnssec")]
    pub(super) fn added(&self) {
        self.zone_records_added.increment(1);
        self.zone_records.increment(1);
    }

    #[cfg(feature = "__dnssec")]
    pub(super) fn deleted(&self) {
        self.zone_records_deleted.increment(1);
        self.zone_records.decrement(1)
    }
    #[cfg(feature = "__dnssec")]
    pub(super) fn updated(&self) {
        self.zone_records_updated.increment(1);
    }
}
