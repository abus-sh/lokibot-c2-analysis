use std::io::{Cursor, Read};

use encoding_rs::{UTF_16LE, UTF_8};

pub struct BodyReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> BodyReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(buffer),
        }
    }

    /// Read exactly `N` bytes from the internal buffer. If there are fewer than `N` bytes
    /// remaining, `None` is returned instead.
    pub fn read_bytes_exact<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut data = [0; N];

        return match self.cursor.read_exact(&mut data) {
            Ok(_) => {
                Some(data)
            },
            Err(err) => {
                None
            }
        };
    }

    /// Note: bools are encoded as two bytes in the packet, so this function also reads two bytes.
    pub fn read_bool(&mut self) -> Option<bool> {
        Some(self.read_u16()? != 0)
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        self.read_bytes_exact::<2>().map(|bytes| {
            u16::from_le_bytes(bytes)
        })
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        self.read_bytes_exact::<4>().map(|bytes| {
            u32::from_le_bytes(bytes)
        })
    }

    pub fn read_string(&mut self) -> Option<String> {
        // Read the string type, 0 is ASCII and anything else is UTF-16-LE
        let str_type = self.read_u16()?;

        // Read the string length
        let str_len = self.read_u32()? as usize;

        // Read the string itself
        let mut str_bytes = Vec::with_capacity(str_len);
        str_bytes.resize(str_len, 0);
        if let Err(_) = self.cursor.read_exact(&mut str_bytes) {
            return None;
        }

        // Use the correct encoding on the string
        let (str_decoded, _, _) = if str_type == 0 {
            UTF_8.decode(&str_bytes)
        } else {
            UTF_16LE.decode(&str_bytes)
        };

        Some(String::from(str_decoded))
    }

    pub fn read_vec(&mut self) -> Option<Vec<u8>> {
        let len = self.read_u32()? as usize;

        let mut vec = Vec::with_capacity(len);
        vec.resize(len, 0);

        if let Err(_) = self.cursor.read_exact(&mut vec) {
            return None;
        }

        Some(vec)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_packet_read() {
        let data = vec![
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
    
        let mut reader = BodyReader::new(&data);

        // Read the packet identifier
        assert_eq!(reader.read_u32().unwrap(), 0x00280012);

        // Read the domain fragment
        assert_eq!(reader.read_string().unwrap(), "ckav.ru");

        // Read the current user, computer name, and comain name
        assert_eq!(reader.read_string().unwrap(), "RE-blck");
        assert_eq!(reader.read_string().unwrap(), "RE-BLCK-PC");
        assert_eq!(reader.read_string().unwrap(), "RE-blck-PC");

        // Read the screen dimensions
        assert_eq!(reader.read_u32().unwrap(), 1462);
        assert_eq!(reader.read_u32().unwrap(), 812);

        // Read admin, local admin, and if the processor is x64
        assert!(reader.read_bool().unwrap());
        assert!(reader.read_bool().unwrap());
        assert!(reader.read_bool().unwrap());

        // Read the Windows version, product type, and one other value
        assert_eq!(reader.read_u16().unwrap(), 6);
        assert_eq!(reader.read_u16().unwrap(), 1);
        assert_eq!(reader.read_u16().unwrap(), 1);
        assert_eq!(reader.read_u16().unwrap(), 0);

        // Read the truncated GUID hash
        assert_eq!(reader.read_string().unwrap(), "EF9F4B6648F07D21A1484590");
    }
}
