use trust_dns_client::client::*;
use trust_dns_client::proto::xfer::{DnsHandle, DnsRequest};
use trust_dns_client::rr::dnssec::*;
use trust_dns_client::rr::rdata::opt::EdnsOption;

#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    pub dnssec_ok: bool,
    pub support_algorithms: Option<SupportedAlgorithms>,
}

impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    pub fn new(client: C) -> Self {
        MutMessageHandle {
            client,
            dnssec_ok: false,
            support_algorithms: None,
        }
    }
}

impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send<R: Into<DnsRequest> + Unpin>(&mut self, request: R) -> Self::Response {
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
