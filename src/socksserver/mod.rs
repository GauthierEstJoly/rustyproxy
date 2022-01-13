pub mod socks_server {
    use std::io::ErrorKind;
    use std::net::ToSocketAddrs;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Mutex,
        thread,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use bytebuffer::ByteBuffer;

    use crate::models::{self, *};

    enum SocksErrorKind {
        CouldNotWrite,
        CouldNotRead,
    }
    async fn reply_with(client: &mut TcpStream, rep: Reply) -> Option<SocksErrorKind> {
        let rp = ReplyPacket {
            version: 5,
            reply: rep,
            reserved: 0,
            dest_address: AdrTypes::IPv4([0, 0, 0, 0]),
            dest_port: 0,
        };

        let mut bb = ByteBuffer::new();
        rp.write(&mut bb);
        if client.write(&bb.to_bytes()).await.is_err() {
            return Some(SocksErrorKind::CouldNotWrite);
        }
        None
    }
    pub struct SocksServer {
        user_pass: Vec<[String; 2]>,
        auth: Authentification,
    }
    impl SocksServer {
        pub fn new() -> Self {
            SocksServer {
                user_pass: Vec::new(),
                auth: Authentification::None,
            }
        }
        pub fn use_auth(&mut self, auth: Authentification) {
            self.auth = auth;
        }
        pub fn set_userpass(&mut self, user_pass: Vec<[String; 2]>) {
            self.user_pass = user_pass;
        }

        pub async fn start(&self, adr: &str) {
            let listener = TcpListener::bind(adr).await.unwrap();
            while let Ok((mut stream, client_addr)) = listener.accept().await {
                let user_pass = self.user_pass.clone();
                let auth = self.auth.clone();
                println!("New client from {:?} !", client_addr);
                tokio::spawn(async move {
                    SocksServer::handle(auth, user_pass, &mut stream).await;
                });
            }
        }

        async fn handle(
            auth: Authentification,
            user_pass: Vec<[String; 2]>,
            client: &mut TcpStream,
        ) {
            if client.set_nodelay(true).is_err() {
                return;
            }
            let mut buf = [0; 16];

            if client.read(&mut buf).await.is_err() {
                return;
            }

            let mut bb = ByteBuffer::from_bytes(&buf);
            let msp = MethodsPacket::new(&mut bb);

            if msp.version != 0x05 {
                return;
            }

            let mut selected_method = Authentification::Unknown;
            if auth == Authentification::UserPassword {
                if msp.methods.contains(&Authentification::UserPassword) {
                    selected_method = Authentification::UserPassword;
                }
            } else {
                selected_method = Authentification::None;
            }

            let ms = SelectedMethodPacket {
                version: 5,
                method: selected_method as u8,
            };

            let mut bb = ByteBuffer::new();
            ms.write(&mut bb);
            if client.write(&bb.to_bytes()).await.is_err() {
                return;
            }

            if selected_method == Authentification::UserPassword {
                let mut buf = [0; 1024];

                if client.read(&mut buf).await.is_err() {
                    return;
                }

                let mut bb = ByteBuffer::from_bytes(&buf);

                bb.read_u8();
                let user_len = bb.read_u8();
                let user = bb.read_bytes(user_len as usize);
                let pass_len = bb.read_u8();
                let pass = bb.read_bytes(pass_len as usize);

                let str_user = match String::from_utf8(user) {
                    Ok(str) => str,
                    Err(_) => String::from("username error"),
                };
                let str_pass = match String::from_utf8(pass) {
                    Ok(str) => str,
                    Err(_) => String::from("password error"),
                };

                let mut found_userpass = false;
                for i in user_pass {
                    if i[0] == str_user && i[1] == str_pass {
                        found_userpass = true;
                        break;
                    }
                }

                if found_userpass {
                    let mut bb = ByteBuffer::new();
                    bb.write_u8(1); // TODO: Make a struct for auth reply
                    bb.write_u8(Reply::Succeeded as u8); // Success
                    if client.write(&bb.to_bytes()).await.is_err() {
                        return;
                    }
                } else {
                    let mut bb = ByteBuffer::new();
                    bb.write_u8(1); // TODO: Make a struct for auth reply
                    bb.write_u8(Reply::Generic as u8); // Failure
                    if client.write(&bb.to_bytes()).await.is_err() {
                        return;
                    }
                    return;
                }

                println!(
                    "Logged in with {} : {} | Found : {}",
                    str_user, str_pass, found_userpass
                );
            }

            let mut buf = [0; 32];

            if client.read(&mut buf).await.is_err() {
                return;
            }

            let mut bb = ByteBuffer::from_bytes(&buf);
            let mut cp = CommandPacket::new(&mut bb);
            if cp.version != 0x05 {
                reply_with(client, Reply::Generic).await;
                return;
            }

            if cp.reserved != 0x00 {
                reply_with(client, Reply::Generic).await;
                return;
            }

            if cp.command as u8 != Command::Connect as u8 {
                reply_with(client, Reply::CommandNotSupported).await;
                return; // TODO: Support more commands (Mostly BIND)
            }

            if let models::AdrTypes::IPv4(addr) = cp.dest_address {
                if addr == [1, 1, 1, 1] {
                    println!("Redirecting 1.1.1.1 to 127.0.0.1");
                    cp.dest_address = models::AdrTypes::IPv4([127, 0, 0, 1]);
                }
            }

            let remote_server = match cp.dest_address {
                AdrTypes::IPv4(x) => {
                    TcpStream::connect(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(x[0], x[1], x[2], x[3])),
                        cp.dest_port,
                    ))
                    .await
                }
                AdrTypes::IPv6(x) => {
                    TcpStream::connect(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(
                            x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
                        )),
                        cp.dest_port,
                    ))
                    .await
                }
                AdrTypes::Domain(x) => {
                    let host = format!("{}:{:?}", x, cp.dest_port).to_socket_addrs();
                    if host.is_err() {
                        println!("1 Host {} is invalide: {:?}", x, host.err().unwrap().kind());
                        return;
                    }
                    let host = host.unwrap().next();
                    if host.is_none() {
                        println!("Host 2 {} is invalide: None", x);
                        return;
                    }
                    TcpStream::connect(host.unwrap()).await
                }
            };

            if remote_server.is_err() {
                match remote_server.err().unwrap().kind() {
                    ErrorKind::ConnectionRefused => {
                        reply_with(client, Reply::ConnectionRefused).await;
                    }
                    ErrorKind::TimedOut => {
                        reply_with(client, Reply::TTLExpired).await;
                    }
                    x => {
                        println!("unknown error : {:?}", x);
                        reply_with(client, Reply::Generic).await;
                    }
                }
                return;
            }

            reply_with(client, Reply::Succeeded).await;

            let mut remote_server = remote_server.unwrap();

            if client.flush().await.is_err() {
                return;
            }

            tokio::io::copy_bidirectional(client, &mut remote_server).await;

            //t.join();
            println!("Thread stopped !");
        }
    }
}
