//! Test interoperability with the nodejs version
//!
//! This will create a bootstrap node and another node that represents stateful
//! nodes in the dht.
//! By running
//!     `cargo run --example local-bs-interop | node js/announce-lookup.test.js`
//! the address of the bootstrap node gets piped to
//! the nodejs program which creates an ephemeral node to announce and
//! afterwards unannouce a topic and a port.
use futures::StreamExt;
use hyperswarm_dht::{DhtConfig, HyperDht};

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bs =
        HyperDht::with_config(DhtConfig::default().empty_bootstrap_nodes().ephemeral()).await?;

    let bs_addr = bs.local_addr()?;

    async_std::task::spawn(async move {
        loop {
            bs.next().await;
        }
    });

    let mut state =
        HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;

    println!("{}", bs_addr);

    loop {
        state.next().await;
    }
}
