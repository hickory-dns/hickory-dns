//! Logging configuration

use log;
use log::{LogLevel, SetLoggerError, LogMetadata, LogRecord};
use chrono::*;

/// The logging manager for the system
#[allow(unused)]
pub struct TrustDnsLogger {
    level: LogLevel,
}

impl TrustDnsLogger {
    /// Configure a logger with the given log level
    pub fn new(level: LogLevel) -> TrustDnsLogger {
        TrustDnsLogger { level: level }
    }

    /// Initializes the logger.
    pub fn init(self) -> Result<(), SetLoggerError> {
        let result = log::set_logger(|max_log_level| {
                                         max_log_level.set(self.level.to_log_level_filter());
                                         Box::new(self)
                                     });

        info!("logging initialized");

        result
    }

    /// Enables the logger with the given `LogLevel`
    pub fn enable_logging(log_level: LogLevel) {
        Self::new(log_level).init().is_ok();
    }
}

impl log::Log for TrustDnsLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let local: DateTime<UTC> = UTC::now();

            println!("{} {} {}:{} {}",
                     local.to_rfc3339(),
                     record.level(),
                     record.location().module_path(),
                     record.location().line(),
                     record.args());
        }
    }
}
