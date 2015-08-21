mod decode_error;
mod encode_error;
mod client_error;

pub use self::decode_error::DecodeError;
pub use self::encode_error::EncodeError;
pub use self::client_error::ClientError;

pub type DecodeResult<T> = Result<T, DecodeError>;
pub type EncodeResult = Result<(), EncodeError>;
pub type ClientResult<T> = Result<T, ClientError>;
