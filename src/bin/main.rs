use rustyproxy::{models::Authentification, socksserver::socks_server::SocksServer};

#[tokio::main]
async fn main() {
    println!("Starting server. . .");
    let mut socks = SocksServer::new();
    socks.use_auth(Authentification::UserPassword);
    socks.set_userpass(vec![
        [String::from("admin"), String::from("admin")],
        [String::from("saucy"), String::from("sauce")],
    ]);
    socks.start("127.0.0.1:6789").await;
}
