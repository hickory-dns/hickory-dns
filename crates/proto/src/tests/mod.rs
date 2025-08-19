//! Tests for TCP and UDP stream and client

#![allow(clippy::print_stdout)] // this is a test module

mod tcp;
mod udp;

pub use self::tcp::tcp_client_stream_test;
pub use self::tcp::tcp_stream_test;
pub use self::udp::next_random_socket_test;
pub use self::udp::udp_client_stream_bad_id_test;
pub use self::udp::udp_client_stream_response_limit_test;
pub use self::udp::udp_client_stream_test;
pub use self::udp::udp_stream_test;
