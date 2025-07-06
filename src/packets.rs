use std::fmt::Display;

use num_enum::TryFromPrimitive;

use crate::encoding::BodyReader;

#[derive(Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum PacketId {
    Beacon = 0x00280012,
    Information = 0x00270012,
    Unknown,
}

#[derive(Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum ProductType {
    VER_NT_WORKSTATION = 1,
    VER_NT_DOMAIN_CONTROLLER = 2,
    VER_NT_SERVER = 3,
}

impl Display for ProductType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VER_NT_WORKSTATION => write!(f, "Workstation"),
            Self::VER_NT_DOMAIN_CONTROLLER => write!(f, "Domain Controller"),
            Self::VER_NT_SERVER => write!(f, "Server"),
        }
    }
}

#[derive(Debug)]
pub enum Packet {
    Beacon(BeaconPacket),
    Information(InformationPacket),
}

impl Packet {
    pub const fn packet_id(&self) -> PacketId {
        match self {
            Self::Beacon {..} => PacketId::Beacon,
            Self::Information {..} => PacketId::Information,
        }
    }

    pub const fn url_fragment(&self) -> &'static str {
        "ckav.ru"
    }
}

impl<'a> TryFrom<&'a [u8]> for Packet {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut reader = BodyReader::new(value);
        
        // Read the packet identifier
        let id = if let Some(id) = reader.read_u32() {
            id
        } else {
            return Err(());
        };

        // Read the domain fragment
        if let Some(domain) = reader.read_string() {
            if domain != "ckav.ru" {
                return Err(());
            }
        } else {
            return Err(());
        }

        // Try to determine the packet type
        let packet_type = if let Ok(id) = PacketId::try_from(id) {
            id
        } else {
            return Err(());
        };

        // Pass the rest of the processing to the relevant packet
        return match packet_type {
            PacketId::Beacon => {
                if let Some(packet) = BeaconPacket::from_reader(&mut reader) {
                    Ok(Self::Beacon(packet))
                } else {
                    Err(())
                }
            },
            PacketId::Information => {
                if let Some(packet) = InformationPacket::from_reader(&mut reader) {
                    Ok(Self::Information(packet))
                } else {
                    Err(())
                }
            }
            _ => Err(())
        };
    }
}

#[derive(Debug)]
pub struct PacketHeader {
    username: String,
    computer_name: String,
    domain_name: String,
    monitor_width: u32,
    monitor_height: u32,
    is_domain_admin: bool,
    is_local_admin: bool,
    is_amd_arch: bool,
    win_major_version: u16,
    win_minor_version: u16,
    win_product_type: ProductType,
    unknown_data: u16,
}

impl PacketHeader {
    fn from_reader(reader: &mut BodyReader) -> Option<Self> {
        Some(Self {
            username: reader.read_string()?,
            computer_name: reader.read_string()?,
            domain_name: reader.read_string()?,
            monitor_width: reader.read_u32()?,
            monitor_height: reader.read_u32()?,
            is_domain_admin: reader.read_bool()?,
            is_local_admin: reader.read_bool()?,
            is_amd_arch: reader.read_bool()?,
            win_major_version: reader.read_u16()?,
            win_minor_version: reader.read_u16()?,
            win_product_type: {
                let win_type = reader.read_u16()?;
                if let Ok(win_type) = ProductType::try_from(win_type) {
                    win_type
                } else {
                    return None;
                }
            },
            unknown_data: reader.read_u16()?,
        })
    }
}

impl Display for PacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User: {}\\{}@{}\n", self.domain_name, self.username, self.computer_name)?;
        write!(f, "Monitor: {} x {}\n", self.monitor_width, self.monitor_height)?;
        write!(f, "Domain administrator: {}\n", self.is_domain_admin)?;
        write!(f, "Local administrator: {}\n", self.is_local_admin)?;
        write!(f, "AMD CPU architecture: {}\n", self.is_amd_arch)?;
        write!(f, "Windows version: {}.{}\n", self.win_major_version, self.win_minor_version)?;
        write!(f, "Windoow type: {}\n", self.win_product_type)?;
        write!(f, "Unknown data: {}\n", self.unknown_data)
    }
}

#[derive(Debug)]
pub struct BeaconPacket {
    header: PacketHeader,
    truncated_guid_hash: String,
}

impl BeaconPacket {
    fn from_reader(reader: &mut BodyReader) -> Option<Self> {
        Some(Self {
            header: PacketHeader::from_reader(reader)?,
            truncated_guid_hash: reader.read_string()?,
        })
    }
}

impl Display for BeaconPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header)?;
        write!(f, "GUID hash: {}\n", self.truncated_guid_hash)
    }
}

#[derive(Debug)]
pub struct InformationPacket {
    header: PacketHeader,
    unknown_short_1: u16,
    unknown_short_2: u16,
    truncated_guid_hash: String,
    buf_1: Vec<u8>,
    buf_2: Vec<u8>,
}

impl InformationPacket {
    fn from_reader(reader: &mut BodyReader) -> Option<Self> {
        let header = PacketHeader::from_reader(reader)?;
        let unknown_short_1 = reader.read_u16()?;
        let unknown_short_2 = reader.read_u16()?;

        // Read hardcoded values
        assert_eq!(reader.read_u16()?, 0);
        assert_eq!(reader.read_u16()?, 0);
        assert_eq!(reader.read_u16()?, 0);

        let buf_len_2 = reader.read_u32()?;

        let truncated_guid_hash = reader.read_string()?;

        let buf_1 = reader.read_vec()?;
        let buf_2 = reader.read_vec()?;

        Some(Self {
            header,
            unknown_short_1,
            unknown_short_2,
            truncated_guid_hash,
            buf_1,
            buf_2,
        })
    }
}

impl Display for InformationPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header)?;
        write!(f, "Unknown data 1: {}\n", self.unknown_short_1)?;
        write!(f, "Unknown data 2: {}\n", self.unknown_short_2)?;
        write!(f, "GUID hash: {}\n", self.truncated_guid_hash)?;
        write!(f, "Buffer 1:\n{:?}\n", self.buf_1)?;
        write!(f, "Buffer 2:\n{:?}\n", self.buf_2)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_beacon_read() {
        let data: Vec<u8> = vec![
            0x12, 0x00, 0x28, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x63, 0x6b, 0x61, 0x76,
            0x2e, 0x72, 0x75, 0x01, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x52, 0x00, 0x45, 0x00, 0x2d,
            0x00, 0x62, 0x00, 0x6c, 0x00, 0x63, 0x00, 0x6b, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00,
            0x00, 0x52, 0x00, 0x45, 0x00, 0x2d, 0x00, 0x42, 0x00, 0x4c, 0x00, 0x43, 0x00, 0x4b,
            0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x52,
            0x00, 0x45, 0x00, 0x2d, 0x00, 0x62, 0x00, 0x6c, 0x00, 0x63, 0x00, 0x6b, 0x00, 0x2d,
            0x00, 0x50, 0x00, 0x43, 0x00, 0xb6, 0x05, 0x00, 0x00, 0x2c, 0x03, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x30, 0x00, 0x00, 0x00, 0x45, 0x00, 0x46, 0x00, 0x39, 0x00, 0x46, 0x00, 0x34,
            0x00, 0x42, 0x00, 0x36, 0x00, 0x36, 0x00, 0x34, 0x00, 0x38, 0x00, 0x46, 0x00, 0x30,
            0x00, 0x37, 0x00, 0x44, 0x00, 0x32, 0x00, 0x31, 0x00, 0x41, 0x00, 0x31, 0x00, 0x34,
            0x00, 0x38, 0x00, 0x34, 0x00, 0x35, 0x00, 0x39, 0x00, 0x30, 0x00
        ];

        let packet = Packet::try_from(data.as_slice())
            .expect("Unable to parse the packet");

        let packet = if let Packet::Beacon(packet) = packet {
            packet
        } else {
            panic!("Packet wasn't a beacon packet")
        };

        assert_eq!(packet.header.username, "RE-blck");
        assert_eq!(packet.header.computer_name, "RE-BLCK-PC");
        assert_eq!(packet.header.domain_name, "RE-blck-PC");

        assert_eq!(packet.header.monitor_width, 1462);
        assert_eq!(packet.header.monitor_height, 812);

        assert!(packet.header.is_domain_admin);
        assert!(packet.header.is_local_admin);
        assert!(packet.header.is_amd_arch);

        assert_eq!(packet.header.win_major_version, 6);
        assert_eq!(packet.header.win_minor_version, 1);
        assert_eq!(packet.header.win_product_type, ProductType::VER_NT_WORKSTATION);
        assert_eq!(packet.header.unknown_data, 0);

        assert_eq!(packet.truncated_guid_hash, "EF9F4B6648F07D21A1484590");
    }

    #[test]
    fn test_information_read() {
        let data: Vec<u8> = vec![
            0x12, 0x00, 0x27, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x63, 0x6b, 0x61, 0x76,
            0x2e, 0x72, 0x75, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x46, 0x00, 0x65, 0x00, 0x6e,
            0x00, 0x67, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x46, 0x00, 0x45, 0x00, 0x4e,
            0x00, 0x47, 0x00, 0x2d, 0x00, 0x43, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x55,
            0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x46,
            0x00, 0x45, 0x00, 0x4e, 0x00, 0x47, 0x00, 0x2d, 0x00, 0x43, 0x00, 0x4f, 0x00, 0x4d,
            0x00, 0x50, 0x00, 0x55, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x80, 0x04, 0x00,
            0x00, 0x60, 0x03, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x6b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x39, 0x00, 0x38,
            0x00, 0x38, 0x00, 0x37, 0x00, 0x36, 0x00, 0x39, 0x00, 0x46, 0x00, 0x31, 0x00, 0x37,
            0x00, 0x37, 0x00, 0x34, 0x00, 0x38, 0x00, 0x43, 0x00, 0x37, 0x00, 0x46, 0x00, 0x38,
            0x00, 0x32, 0x00, 0x34, 0x00, 0x37, 0x00, 0x39, 0x00, 0x35, 0x00, 0x37, 0x00, 0x36,
            0x00, 0x36, 0x00, 0x05, 0x00, 0x00, 0x00, 0x69, 0x50, 0x69, 0x50, 0x32, 0x00, 0x00,
            0x00, 0x00
        ];

        let packet = Packet::try_from(data.as_slice())
            .expect("Unable to parse the packet");

        let packet = if let Packet::Information(packet) = packet {
            packet
        } else {
            panic!("Packet wasn't a beacon packet")
        };

        assert_eq!(packet.header.username, "Feng");
        assert_eq!(packet.header.computer_name, "FENG-COMPUTER");
        assert_eq!(packet.header.domain_name, "FENG-COMPUTER");

        assert_eq!(packet.header.monitor_width, 1152);
        assert_eq!(packet.header.monitor_height, 864);

        assert!(packet.header.is_domain_admin);
        assert!(packet.header.is_local_admin);
        assert!(!packet.header.is_amd_arch);

        assert_eq!(packet.header.win_major_version, 5);
        assert_eq!(packet.header.win_minor_version, 1);
        assert_eq!(packet.header.win_product_type, ProductType::VER_NT_WORKSTATION);
        assert_eq!(packet.header.unknown_data, 107);

        assert_eq!(packet.unknown_short_1, 0);
        assert_eq!(packet.truncated_guid_hash, "988769F17748C7F824795766");

        assert_eq!(packet.buf_1, vec![0x69, 0x50, 0x69, 0x50, 0x32]);
        assert_eq!(packet.buf_2, Vec::<u8>::new());
    }
}
