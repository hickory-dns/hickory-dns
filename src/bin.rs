extern crate trust_dns;
extern crate rustc_serialize;
extern crate docopt;
#[macro_use] extern crate log;

use log::LogLevel;
use docopt::Docopt;

use trust_dns::logger;
use trust_dns::version;

// Write the Docopt usage string.
const USAGE: &'static str = "
Usage: named [options]
       named (-h | --help | --version)

Options:
    -q, --quiet        Disable INFO messages, WARN and ERROR will remain
    -d, --debug        Turn on DEBUG messages (default is only INFO)
    -h, --help         Show this message.
    -v, --version      Show the version of trust-dns.
";

#[derive(RustcDecodable)]
struct Args {
  pub flag_quiet: bool,
  pub flag_debug: bool,
  pub flag_help: bool,
  pub flag_version: bool,
}

pub fn main() {
  // read any command line options
  let args: Args = Docopt::new(USAGE)
                        .and_then(|d| d.help(true).version(Some(trust_dns::version().into())).decode())
                        .unwrap_or_else(|e| e.exit());

  if args.flag_quiet {
    logger::TrustDnsLogger::enable_logging(LogLevel::Warn);
  } else if args.flag_debug {
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);
  } else {
    logger::TrustDnsLogger::enable_logging(LogLevel::Info);
  }

  info!("Trust-DNS {} starting", trust_dns::version());
  // start up the server for listening



  // we're exiting for some reason...
  info!("Trust-DNS {} stopping", trust_dns::version());
}
