use hickory_client::client::ClientHandle;
#[cfg(feature = "dnssec-ring")]
use hickory_proto::op::Edns;
use hickory_proto::xfer::{DnsHandle, DnsRequest};
#[cfg(feature = "dnssec-ring")]
use hickory_server::authority::LookupOptions;

#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    #[cfg(feature = "dnssec-ring")]
    pub lookup_options: LookupOptions,
}

impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    #[allow(dead_code)]
    pub fn new(client: C) -> Self {
        MutMessageHandle {
            client,
            #[cfg(feature = "dnssec-ring")]
            lookup_options: Default::default(),
        }
    }
}

impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    #[allow(unused_mut)]
    fn send<R: Into<DnsRequest> + Unpin>(&self, request: R) -> Self::Response {
        let mut request = request.into();

        #[cfg(feature = "dnssec-ring")]
        {
            // mutable block
            let edns = request.extensions_mut().get_or_insert_with(Edns::new);
            edns.set_dnssec_ok(true);
        }

        println!("sending message");
        self.client.send(request)
    }
}
