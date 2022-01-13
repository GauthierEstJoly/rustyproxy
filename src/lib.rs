pub mod socksserver;

pub mod models {

    use bytebuffer::ByteBuffer;

    pub trait WritePacket {
        fn write(&self, bb: &mut ByteBuffer); // Write packet to ByteBuffer
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Authentification {
        None = 0,
        UserPassword = 2,
        Unknown = 255,
    }
    impl From<u8> for Authentification {
        fn from(v: u8) -> Self {
            match v {
                x if x == Authentification::None as u8 => Authentification::None,
                x if x == Authentification::UserPassword as u8 => Authentification::UserPassword,
                _ => Authentification::Unknown,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub enum AdrTypes {
        IPv4([u8; 4]),
        IPv6([u16; 8]),
        Domain(String),
    }
    impl AdrTypes {
        fn read(bb: &mut ByteBuffer) -> Self {
            let adr_type = bb.read_u8();
            match adr_type {
                0x01 => AdrTypes::IPv4([bb.read_u8(), bb.read_u8(), bb.read_u8(), bb.read_u8()]),
                0x03 => {
                    let domain_len = bb.read_u8();
                    let domain = bb.read_bytes(domain_len as usize);
                    AdrTypes::Domain(match String::from_utf8(domain) {
                        Ok(x) => x,
                        Err(_) => String::from("localhost"),
                    })
                }
                0x04 => AdrTypes::IPv6([
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                    bb.read_u16(),
                ]),
                _ => AdrTypes::IPv4([0, 0, 0, 0]),
            }
        }
        fn write(&self, bb: &mut ByteBuffer) {
            match self {
                AdrTypes::IPv4(x) => {
                    bb.write_u8(1);
                    bb.write_bytes(x);
                }
                AdrTypes::IPv6(x) => {
                    bb.write_u8(3);
                    for b in x {
                        bb.write_u16(*b);
                    }
                }
                AdrTypes::Domain(x) => {
                    bb.write_u8(x.len() as u8);
                    bb.write_bytes(x.as_bytes());
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub enum Command {
        Connect = 1,
        Bind = 2,
        UdpAssociate = 3,
        Unknown = 255,
    }
    impl From<u8> for Command {
        fn from(v: u8) -> Self {
            match v {
                x if x == Command::Connect as u8 => Command::Connect,
                x if x == Command::Bind as u8 => Command::Bind,
                x if x == Command::UdpAssociate as u8 => Command::UdpAssociate,
                _ => Command::Unknown,
            }
        }
    }
    #[derive(Clone, Copy, Debug)]
    pub enum Reply {
        Succeeded = 0,
        Generic = 1,
        NotAllowedByRuleSet = 2,
        NetworkUnreachable = 3,
        HostUnreachable = 4,
        ConnectionRefused = 5,
        TTLExpired = 6,
        CommandNotSupported = 7,
        AddressTypeNotSupported = 8,
        Unknown = 255,
    }
    impl From<u8> for Reply {
        fn from(v: u8) -> Self {
            match v {
                x if x == Reply::Succeeded as u8 => Reply::Succeeded,
                x if x == Reply::Generic as u8 => Reply::Generic,
                x if x == Reply::NotAllowedByRuleSet as u8 => Reply::NotAllowedByRuleSet,
                x if x == Reply::NetworkUnreachable as u8 => Reply::NetworkUnreachable,
                x if x == Reply::HostUnreachable as u8 => Reply::HostUnreachable,
                x if x == Reply::ConnectionRefused as u8 => Reply::ConnectionRefused,
                x if x == Reply::TTLExpired as u8 => Reply::TTLExpired,
                x if x == Reply::CommandNotSupported as u8 => Reply::CommandNotSupported,
                x if x == Reply::AddressTypeNotSupported as u8 => Reply::AddressTypeNotSupported,

                _ => Reply::Unknown,
            }
        }
    }
    #[derive(Debug)]
    pub struct MethodsPacket {
        pub version: u8,
        pub nb_methods: u8,
        pub methods: Vec<Authentification>,
    }
    impl MethodsPacket {
        pub fn new(bb: &mut ByteBuffer) -> Self {
            let version = bb.read_u8();
            let nb_methods = bb.read_u8();

            let mut vec_auth: Vec<Authentification> = Vec::new();
            for _ in 0..nb_methods {
                vec_auth.push(bb.read_u8().into());
            }

            MethodsPacket {
                version,
                nb_methods,
                methods: vec_auth,
            }
        }
    }
    impl WritePacket for MethodsPacket {
        fn write(&self, bb: &mut ByteBuffer) {
            bb.write_u8(self.version);
            bb.write_u8(self.nb_methods);
            for i in self.methods.iter() {
                bb.write_u8(*i as u8);
            }
        }
    }
    #[derive(Debug)]
    pub struct SelectedMethodPacket {
        pub version: u8,
        pub method: u8,
    }
    impl SelectedMethodPacket {
        fn new(bb: &mut ByteBuffer) -> Self {
            let version = bb.read_u8();
            let method = bb.read_u8();
            SelectedMethodPacket { version, method }
        }
    }
    impl WritePacket for SelectedMethodPacket {
        fn write(&self, bb: &mut ByteBuffer) {
            bb.write_u8(self.version);
            bb.write_u8(self.method);
        }
    }

    #[derive(Debug)]
    pub struct CommandPacket {
        pub version: u8,
        pub command: Command,
        pub reserved: u8,
        pub dest_address: AdrTypes,
        pub dest_port: u16,
    }
    impl CommandPacket {
        pub fn new(bb: &mut ByteBuffer) -> Self {
            let version = bb.read_u8();
            let command: Command = bb.read_u8().into();
            let reserved = bb.read_u8();

            let dest_address = AdrTypes::read(bb);

            let dest_port = bb.read_u16();

            CommandPacket {
                version,
                command,
                reserved,
                dest_address,
                dest_port,
            }
        }
    }
    impl WritePacket for CommandPacket {
        fn write(&self, bb: &mut ByteBuffer) {
            bb.write_u8(self.version);
            bb.write_u8(self.command as u8);
            bb.write_u8(self.reserved);
            self.dest_address.write(bb);
            bb.write_u16(self.dest_port);
        }
    }
    #[derive(Debug)]
    pub struct ReplyPacket {
        pub version: u8,
        pub reply: Reply,
        pub reserved: u8,
        pub dest_address: AdrTypes,
        pub dest_port: u16,
    }
    impl ReplyPacket {
        fn new(bb: &mut ByteBuffer) -> Self {
            let version = bb.read_u8();
            let reply: Reply = bb.read_u8().into();
            let reserved = bb.read_u8();
            let dest_address = AdrTypes::read(bb);
            let dest_port = bb.read_u16();
            ReplyPacket {
                version,
                reply,
                reserved,
                dest_address,
                dest_port,
            }
        }
    }
    impl WritePacket for ReplyPacket {
        fn write(&self, bb: &mut ByteBuffer) {
            bb.write_u8(self.version);
            bb.write_u8(self.reply as u8);
            bb.write_u8(self.reserved);
            self.dest_address.write(bb);
            bb.write_u16(self.dest_port);
        }
    }
}
