use futures::future::*;

use trust_dns::client::*;
use trust_dns::error::*;
use trust_dns::op::*;

#[derive(Clone)]
pub struct MutMessageClient<C: ClientHandle> {
    client: C,
    pub dnssec_ok: bool,
}

impl<C: ClientHandle> MutMessageClient<C> {
    pub fn new(client: C) -> Self {
        MutMessageClient {
            client,
            dnssec_ok: false,
        }
    }
}

impl<C: ClientHandle> ClientHandle for MutMessageClient<C> {
    fn send(&mut self, mut message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        {
            // mutable block
            let mut edns = message.edns_mut();
            edns.set_dnssec_ok(true);
        }

        self.client.send(message)
    }
}