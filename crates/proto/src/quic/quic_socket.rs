// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{Debug, Formatter};
use std::{
    fmt,
    task::{Context, Poll},
};

use quinn::AsyncUdpSocket;

use crate::udp::{DnsUdpSocket, QuicLocalAddr};

/// Wrapper used for quinn::Endpoint::new_with_abstract_socket
pub(crate) struct QuinnAsyncUdpSocketAdapter<S: DnsUdpSocket + QuicLocalAddr> {
    pub(crate) io: S,
}

impl<S: DnsUdpSocket + QuicLocalAddr> Debug for QuinnAsyncUdpSocketAdapter<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Wrapper for quinn::AsyncUdpSocket")
    }
}

/// TODO: Naive implementation. Look forward to future improvements.
impl<S: DnsUdpSocket + QuicLocalAddr + 'static> AsyncUdpSocket for QuinnAsyncUdpSocketAdapter<S> {
    fn poll_send(
        &self,
        _state: &quinn::udp::UdpState,
        cx: &mut Context<'_>,
        transmits: &[quinn::udp::Transmit],
    ) -> Poll<std::io::Result<usize>> {
        // logics from quinn-udp::fallback.rs
        let io = &self.io;
        let mut sent = 0;
        for transmit in transmits {
            match io.poll_send_to(cx, &transmit.contents, transmit.destination) {
                Poll::Ready(ready) => match ready {
                    Ok(_) => {
                        sent += 1;
                    }
                    // We need to report that some packets were sent in this case, so we rely on
                    // errors being either harmlessly transient (in the case of WouldBlock) or
                    // recurring on the next call.
                    Err(_) if sent != 0 => return Poll::Ready(Ok(sent)),
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            return Poll::Ready(Err(e));
                        }

                        // Other errors are ignored, since they will ususally be handled
                        // by higher level retransmits and timeouts.
                        // - PermissionDenied errors have been observed due to iptable rules.
                        //   Those are not fatal errors, since the
                        //   configuration can be dynamically changed.
                        // - Destination unreachable errors have been observed for other
                        // log_sendmsg_error(&mut self.last_send_error, e, transmit);
                        sent += 1;
                    }
                },
                Poll::Pending => {
                    return if sent == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(sent))
                    }
                }
            }
        }
        Poll::Ready(Ok(sent))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        // logics from quinn-udp::fallback.rs

        let io = &self.io;
        let Some(buf) = bufs.get_mut(0) else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no buf",
            )));
        };
        match io.poll_recv_from(cx, buf.as_mut()) {
            Poll::Ready(res) => match res {
                Ok((len, addr)) => {
                    meta[0] = quinn::udp::RecvMeta {
                        len,
                        stride: len,
                        addr,
                        ecn: None,
                        dst_ip: None,
                    };
                    Poll::Ready(Ok(1))
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }
}
