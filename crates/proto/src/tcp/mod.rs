/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! TCP protocol related components for DNS
mod tcp_client_stream;
mod tcp_stream;

pub use self::tcp_client_stream::{TcpClientConnect, TcpClientStream};
pub use self::tcp_stream::{Connect, DnsTcpStream, TcpStream};

#[cfg(feature = "tokio-runtime")]
#[doc(hidden)]
pub mod tokio {
    use std::io;
    use std::net::SocketAddr;
    use tokio::net::TcpSocket as TokioTcpSocket;
    use tokio::net::TcpStream as TokioTcpStream;

    pub async fn connect(addr: &SocketAddr) -> Result<TokioTcpStream, io::Error> {
        connect_with_bind(addr, &None).await
    }

    pub async fn connect_with_bind(
        addr: &SocketAddr,
        bind_addr: &Option<SocketAddr>,
    ) -> Result<TokioTcpStream, io::Error> {
        let stream = match bind_addr {
            Some(bind_addr) => {
                let socket = match bind_addr {
                    SocketAddr::V4(_) => TokioTcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TokioTcpSocket::new_v6()?,
                };
                socket.bind(*bind_addr)?;
                socket.connect(*addr).await?
            }
            None => TokioTcpStream::connect(addr).await?,
        };
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}
