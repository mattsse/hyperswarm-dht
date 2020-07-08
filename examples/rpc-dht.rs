use futures::StreamExt;
use hyperswarm_dht::rpc::{Dht, DhtConfig, DhtEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    if let Some(bootstrap) = std::env::args().nth(1) {
        println!("{}", bootstrap);

        let mut b = Dht::with_config(
            DhtConfig::default()
                .set_bootstrap_nodes(&[bootstrap])
                .bind("127.0.0.1:3402")
                .await
                .expect("Failed to create dht with socket"),
        )
        .await
        .expect("Failed to create dht with socket");

        b.bootstrap();

        loop {
            println!("looping b");
            if let Some(event) = b.next().await {
                match event {
                    DhtEvent::RequestResult(res) => println!("b request result {:?}", res),
                    DhtEvent::ResponseResult(res) => println!("b response result {:?}", res),
                    DhtEvent::RemovedBadIdNode(_) => println!("b removed bad id node"),
                    DhtEvent::RoutingUpdated { .. } => println!("b routing updated"),
                    DhtEvent::QueryResult { .. } => println!("b query result"),
                }
            }
        }
    } else {
        let mut a = Dht::with_config(
            DhtConfig::default()
                .bind("127.0.0.1:3401")
                .await
                .expect("Failed to create dht with socket"),
        )
        .await
        .expect("Failed to create dht with socket");

        let work = tokio::spawn(async move {
            loop {
                if let Some(event) = a.next().await {
                    match event {
                        DhtEvent::RequestResult(res) => println!("request result {:?}", res),
                        DhtEvent::ResponseResult(_) => println!("response result"),
                        DhtEvent::RemovedBadIdNode(_) => println!("removed bad id node"),
                        DhtEvent::RoutingUpdated { .. } => println!("routing updated"),
                        DhtEvent::QueryResult { .. } => println!("query result"),
                    }
                }
            }
        });

        work.await;
    }

    Ok(())
}
