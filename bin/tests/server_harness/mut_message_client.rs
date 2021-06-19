use trust_dns_client::client::*;
use trust_dns_client::proto::xfer::{DnsHandle, DnsRequest};
#[cfg(feature = "dnssec")]
use trust_dns_client::rr::rdata::opt::EdnsOption;
use trust_dns_server::authority::LookupOptions;

#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    pub lookup_options: LookupOptions,
}

impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    #[allow(dead_code)]
    pub fn new(client: C) -> Self {
        MutMessageHandle {
            client,
            lookup_options: Default::default(),
        }
    }
}

impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;
    type Error = <C as DnsHandle>::Error;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    #[allow(unused_mut)]
    fn send<R: Into<DnsRequest> + Unpin>(&mut self, request: R) -> Self::Response {
        let mut request = request.into();

        #[cfg(feature = "dnssec")]
        {
            // mutable block
            let edns = request.edns_mut();
            edns.set_dnssec_ok(true);
            edns.options_mut()
                .insert(EdnsOption::DAU(self.lookup_options.supported_algorithms()));
        }

        println!("sending message");
        self.client.send(request)
    }
}
