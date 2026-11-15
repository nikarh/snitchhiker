//! Nodes over the network (iroh): connecting as a paired device, and pairing with a link's one-time secret.

use snitchhiker_proto::{frame, v1};
use snitchhiker_remote::{ALPN, Key, NodeAddress, Options, PAIR_ALPN, PairLink};

use crate::{Client, Error};

/// Connects to a node this device is paired with.
pub fn connect(
    key: &Key,
    node: &NodeAddress,
    options: &Options,
    app: &str,
    version: &str,
) -> Result<Client, Error> {
    let connected = snitchhiker_remote::connect(key, node, options, ALPN)?;
    Client::handshake(connected.stream, Some(connected.keep), app, version)
}

/// Pairs this device (`key`, called `name`) with the node of `link`; the node's answer.
pub fn pair(
    key: &Key,
    link: &PairLink,
    name: &str,
    options: &Options,
) -> Result<v1::PairResponse, Error> {
    let connected = snitchhiker_remote::connect(key, &link.node, options, PAIR_ALPN)?;
    let mut stream = &connected.stream;
    let request = v1::PairRequest {
        secret: link.secret.clone(),
        device_name: name.to_owned(),
    };
    let mut buffer = Vec::new();
    frame::write(&mut stream, &request, &mut buffer)?;
    let response: v1::PairResponse =
        frame::read(&mut std::io::BufReader::new(stream), &mut buffer)?;
    if response.error.is_empty() {
        Ok(response)
    } else {
        Err(Error::Refused(response.error))
    }
}
