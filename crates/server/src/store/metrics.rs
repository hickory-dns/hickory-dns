use crate::authority::{LookupControlFlow, LookupObject};
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

pub(super) struct QueryStoreMetrics {
    pub(super) zone_record_lookups_success: Counter,
    pub(super) zone_record_lookups_error: Counter,
}

impl QueryStoreMetrics {
    pub(crate) fn new(store: &'static str) -> Self {
        let zone_record_lookups_name = "hickory_zone_record_lookups_total";
        let store_key = "store";
        let success_key = "success";

        let zone_record_lookups_success =
            counter!(zone_record_lookups_name, store_key => store, success_key => "true");
        let zone_record_lookups_error =
            counter!(zone_record_lookups_name, store_key => store, success_key => "false");

        describe_counter!(
            zone_record_lookups_name,
            Unit::Count,
            "number of occurred dns zone record lookups"
        );

        Self {
            zone_record_lookups_success,
            zone_record_lookups_error,
        }
    }

    pub(super) fn increment_lookup<T: LookupObject>(
        &self,
        lookup_control_flow: &LookupControlFlow<T>,
    ) {
        let is_success = match lookup_control_flow {
            LookupControlFlow::Continue(res) => res.is_ok(),
            LookupControlFlow::Break(res) => res.is_ok(),
            LookupControlFlow::Skip => false,
        };

        if is_success {
            self.zone_record_lookups_success.increment(1)
        } else {
            self.zone_record_lookups_error.increment(1)
        }
    }
}
