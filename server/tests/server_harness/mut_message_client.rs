use futures::future::*;

use trust_dns::client::*;
use trust_dns::error::*;
use trust_dns::rr::dnssec::*;
use trust_dns::rr::rdata::opt::EdnsOption;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle> {
    client: C,
    pub dnssec_ok: bool,
    pub support_algorithms: Option<SupportedAlgorithms>,
}

impl<C: ClientHandle> MutMessageHandle<C> {
    pub fn new(client: C) -> Self {
        MutMessageHandle {
            client,
            dnssec_ok: false,
            support_algorithms: None,
        }
    }
}

impl<C: ClientHandle> DnsHandle for MutMessageHandle<C> {
    type Error = ClientError;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send<R: Into<DnsRequest>>(
        &mut self,
        request: R,
    ) -> Box<Future<Item = DnsResponse, Error = Self::Error>> {
        let mut request = request.into();
        {
            // mutable block
            let edns = request.edns_mut();
            edns.set_dnssec_ok(true);

            if let Some(supported_algs) = self.support_algorithms {
                edns.set_option(EdnsOption::DAU(supported_algs));
            }
        }

        println!("sending message");
        self.client.send(request)
    }
}
