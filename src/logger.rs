use log;
use log::{LogLevel, SetLoggerError, LogMetadata, LogRecord};

#[allow(unused)]
pub struct TrustDnsLogger { level: LogLevel }

impl TrustDnsLogger {
  #[allow(dead_code)]
  pub fn new(level: LogLevel) -> TrustDnsLogger {
    TrustDnsLogger { level: level }
  }

  #[allow(dead_code)]
  pub fn init(self) -> Result<(), SetLoggerError> {
    let result = log::set_logger(|max_log_level| {
        max_log_level.set(self.level.to_log_level_filter());
        Box::new(self)
    });

    info!("logging initialized");

    result
  }
}

impl log::Log for TrustDnsLogger {
  fn enabled(&self, metadata: &LogMetadata) -> bool {
    metadata.level() <= self.level
  }

  fn log(&self, record: &LogRecord) {
    if self.enabled(record.metadata()) {
      println!("{} {}:{} {}", record.level(), record.location().module_path(), record.location().line(), record.args());
    }
  }
}
