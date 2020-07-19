use futures::StreamExt;
use hyperswarm_dht::{DhtConfig, HyperDht, HyperDhtEvent, IdBytes, QueryOpts};

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    if let Some(bootstrap) = std::env::args().nth(1) {
        println!("{}", bootstrap);

        let mut state =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bootstrap]).ephemeral())
                .await
                .expect("Failed to create dht with socket");

        async_std::task::spawn(async move {
            println!("state addr {:?}", state.local_addr());
            loop {
                if let Some(event) = state.next().await {}
            }
        });

        // send from state to node as soon as bootstrapping done with channel
        let mut node = HyperDht::with_config(
            DhtConfig::default()
                .set_bootstrap_nodes(&[&bootstrap])
        )
        .await
        .expect("Failed to create dht with socket");

        println!("node addr {:?}", node.local_addr());

        let opts = QueryOpts::new(IdBytes::random()).port(12345);
        let announce = node.announce(opts.clone());

        loop {
            if let Some(event) = node.next().await {
                match event {
                    HyperDhtEvent::AnnounceResult {
                        peers,
                        topic,
                        query_id,
                    } => {
                        // assert_eq!(query_id, announce);
                        println!("announced to {:?}", peers);
                        node.lookup(opts.clone());
                    }
                    HyperDhtEvent::UnAnnounceResult { .. } => {}
                    HyperDhtEvent::LookupResult {
                        peers,
                        topic,
                        query_id,
                    } => {
                        assert_eq!(topic, opts.topic);
                        println!("lookedup {:?}", peers);
                        node.unannounce(opts.clone());
                    }
                    HyperDhtEvent::CustomCommandQuery { .. } => {}
                }
            }
        }
    } else {
        // in order to bootstrap we start an ephemeral node with empty bootstrap array
        let mut bootstrap = HyperDht::with_config(
            DhtConfig::default()
                .empty_bootstrap_nodes()
                .ephemeral()
                .bind("127.0.0.1:3402")
                .await
                .expect("Failed to create dht with socket"),
        )
        .await
        .expect("Failed to create dht with socket");

        println!("bootstrap node listening on {:?}", bootstrap.local_addr());

        loop {
            bootstrap.next().await;
        }
    }
}
