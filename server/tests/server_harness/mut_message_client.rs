use futures::future::*;

use trust_dns::client::*;
use trust_dns::rr::dnssec::*;
use trust_dns::rr::rdata::opt::EdnsOption;
use trust_dns::error::*;
use trust_dns::op::*;
use trust_dns_proto::DnsHandle;

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

    fn send(&mut self, mut message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        {
            // mutable block
            let edns = message.edns_mut();
            edns.set_dnssec_ok(true);

            if let Some(supported_algs) = self.support_algorithms {
                edns.set_option(EdnsOption::DAU(supported_algs));
            }
        }

        println!("sending message");
        self.client.send(message)
    }
}
