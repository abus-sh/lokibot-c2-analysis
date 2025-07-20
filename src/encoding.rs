use std::{ffi::CString, io::{Cursor, Read, Write}};

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

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    ops: Vec<Operation>,
}

impl Response {
    pub fn new(ops: Vec<Operation>) -> Self {
        Self {
            ops,
        }
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            ops: Vec::new(),
        }
    }
}

// From is used rather than TryFrom since the only possible failure is a memory allocation error,
// which would already cause other issues.
impl From<Response> for Vec<u8> {
    fn from(value: Response) -> Self {
        let mut response = Vec::new();

        // Write a temporary byte, this will later be replaced with the length
        response.write(&[9, 0, 0, 0])
            .expect("unable to write response");

        // Write the number of commands
        response.write(&(value.ops.len() as u32)
            .to_le_bytes()).expect("unable to write response");

        // Write the commands
        for op in value.ops {
            let bytes = Vec::<u8>::from(op);
            response.write(&bytes).expect("unable to write response");
        }

        // Copy the final length
        let len: [u8; 4] = (response.len() as u32).to_le_bytes();
        response[..4].clone_from_slice(&len);

        response
    }
}

impl TryFrom<&mut &[u8]> for Response {
    type Error = ();

    fn try_from(value: &mut &[u8]) -> Result<Self, Self::Error> {
        let mut buf = [0u8; 4];

        // Read the length, make sure we have at least that many bytes
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }
        // +4 to account for the 4 bytes already read
        if (u32::from_le_bytes(buf) as usize) > value.len() + 4 {
            return Err(());
        }

        // Read the number of ops
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }
        let num_ops = u32::from_le_bytes(buf);

        let mut ops = Vec::with_capacity(num_ops as usize);
        for _ in 0..num_ops {
            let op = match Operation::try_from(&mut *value) {
                Ok(o) => o,
                Err(_e) => return Err(()),
            };
            ops.push(op);
        }

        Ok(Response {
            ops,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Operation {
    opcode: OpCode,
    arg: String,
}

impl Operation {
    pub fn new(opcode: OpCode, arg: String) -> Self {
        Self {
            opcode,
            arg,
        }
    }
}

// From is used rather than TryFrom since the only possible failure is a memory allocation error,
// which would already cause other issues.
impl From<Operation> for Vec<u8> {
    fn from(value: Operation) -> Self {
        // Byte format - (unused u32) + (opcode) + (unused u32) + (arg len) + (arg) + (null u32)
        const BLANK_WORD: [u8; 4] = [0; 4];

        // Create a vec with the correct capacity (4 `u32`s, the arg, and the null byte)
        let mut out_buf = Vec::with_capacity(17 + value.arg.len());

        // First unused word
        out_buf.write(&BLANK_WORD)
            .expect("already allocated enough space.");

        // Opcode
        out_buf.write(&(value.opcode as u32).to_le_bytes())
            .expect("already allocated enough space.");

        // Second unused word
        out_buf.write(&BLANK_WORD)
            .expect("already allocated enough space.");

        // Arg length + null byte
        out_buf.write(&(value.arg.len() as u32 + 1).to_le_bytes())
            .expect("already allocated enough space.");

        // The arg itself
        out_buf.write(&value.arg.as_bytes())
            .expect("already allocated enough space.");

        out_buf.write(&[0])
            .expect("already allocated enough space.");

        out_buf
    }
}

impl TryFrom<&mut &[u8]> for Operation {
    type Error = ();

    fn try_from(value: &mut &[u8]) -> Result<Self, Self::Error> {
        let mut buf: [u8; 4] = [0; 4];

        // Read first ignored word, make sure it isn't u32::MAX
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }
        if u32::from_le_bytes(buf) == u32::MAX {
            return Err(());
        }

        // Read opcode
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }
        let opcode: OpCode = match u32::from_le_bytes(buf).try_into() {
            Ok(o) => o,
            Err(_e) => return Err(()),
        };

        // Read second ignored word
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }

        // Read the string length
        if let Err(_e) = value.read_exact(&mut buf) {
            return Err(());
        }

        // Read the string if non-zero length (length includes null byte)
        let str_len = u32::from_le_bytes(buf);
        let arg = match str_len {
            // Allow 0 length strings, assume it means an empty string and no null byte was sent 
            0 => String::from(""),
            n => {
                // Allocate a Vec of the correct size and expand it to the correct size
                let mut str = Vec::with_capacity(n as usize);
                str.resize(n as usize, 0);

                // Read the string
                if let Err(_e) = value.read_exact(&mut str) {
                    return Err(());
                }

                // Attempt to convert the Vec into a CString
                // TODO: should this fall back to String::try_from(Vec) if there is no null byte?
                let str = match CString::from_vec_with_nul(str) {
                    Ok(s) => s,
                    Err(_e) => return Err(()),
                };
                
                // Attempt to convert the CString into a String
                let str = match str.into_string() {
                    Ok(s) => s,
                    Err(_e) => return Err(()),
                };

                // Make sure the length is correct (including null byte)
                if str.len() + 1 != n as usize {
                    return Err(())
                };

                str
            },
        };

        Ok(Operation {
            opcode,
            arg,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OpCode {
    StealInfo = 10,
    DownloadExe1 = 0,
    DownloadDll = 1,
    DownloadExe2 = 2,
    DeleteFile = 8,
    ExitProcess = 14,
    DownloadExe3 = 15,
    SetGlobal = 16,
    MoveAndExit = 17,
}

impl TryFrom<u32> for OpCode {
    type Error = ();
    
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == OpCode::StealInfo as u32 => Ok(OpCode::StealInfo),
            x if x == OpCode::DownloadExe1 as u32 => Ok(OpCode::DownloadExe1),
            x if x == OpCode::DownloadDll as u32 => Ok(OpCode::DownloadDll),
            x if x == OpCode::DownloadExe2 as u32 => Ok(OpCode::DownloadExe2),
            x if x == OpCode::DeleteFile as u32 => Ok(OpCode::DeleteFile),
            x if x == OpCode::ExitProcess as u32 => Ok(OpCode::ExitProcess),
            x if x == OpCode::DownloadExe3 as u32 => Ok(OpCode::DownloadExe3),
            x if x == OpCode::SetGlobal as u32 => Ok(OpCode::SetGlobal),
            x if x == OpCode::MoveAndExit as u32 => Ok(OpCode::MoveAndExit),
            _ => Err(()),
        }
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

    #[test]
    fn test_opcode() {
        // Test enum to u32
        assert_eq!(OpCode::StealInfo as u32, 10);
        assert_eq!(OpCode::DownloadExe1 as u32, 0);
        assert_eq!(OpCode::DownloadDll as u32, 1);
        assert_eq!(OpCode::DownloadExe2 as u32, 2);
        assert_eq!(OpCode::DeleteFile as u32, 8);
        assert_eq!(OpCode::ExitProcess as u32, 14);
        assert_eq!(OpCode::DownloadExe3 as u32, 15);
        assert_eq!(OpCode::SetGlobal as u32, 16);
        assert_eq!(OpCode::MoveAndExit as u32, 17);

        // Test valid u32 to enum
        assert_eq!(OpCode::StealInfo, 10.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::DownloadExe1, 0.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::DownloadDll, 1.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::DownloadExe2, 2.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::DeleteFile, 8.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::ExitProcess, 14.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::DownloadExe3, 15.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::SetGlobal, 16.try_into().expect("valid u32 not allowed"));
        assert_eq!(OpCode::MoveAndExit, 17.try_into().expect("valid u32 not allowed"));

        // Test invalid u32 to enum
        for i in 3..=7 {
            OpCode::try_from(i).expect_err("invalid u32 allowed");
        }
        OpCode::try_from(9).expect_err("invalid u32 allowed");
        for i in 11..=13 {
            OpCode::try_from(i).expect_err("invalid u32 allowed");
        }
        for i in 18..256 {
            OpCode::try_from(i).expect_err("invalid u32 allowed");
        }
    }

    #[test]
    fn test_operation_encoding() {
        let op = Operation {
            opcode: OpCode::DeleteFile,
            arg: String::from("ab"),
        };
        let bytes: Vec<u8> = op.into();
        assert_eq!(bytes, [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            3, 0, 0, 0, // Arg length + null byte
            97, 98, 0,  // The arg + null byte
        ], "valid operation not encoded properly");

        let op = Operation {
            opcode: OpCode::DownloadExe1,
            arg: String::from(""),
        };
        let bytes: Vec<u8> = op.into();
        assert_eq!(bytes, [
            0, 0, 0, 0, // Ignored word
            0, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            1, 0, 0, 0, // Arg length + null byte
            0,          // The arg + null byte
        ], "empty arg operation not encoded properly");
    }

    #[test]
    fn test_operation_decoding() {
        let bytes: [u8; 0] = [];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("empty bytes allowed");

        let bytes = [
            255, 255, 255, 255, // Ignored word
            8, 0, 0, 0,         // Opcode (le)
            0, 0, 0, 0,         // Ignored word
            3, 0, 0, 0,         // Arg length + null byte
            97, 98, 0,          // The arg + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("invalid first word allowed");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            3, 0, 0, 0, // Opcode (le, invalid)
            0, 0, 0, 0, // Ignored word
            3, 0, 0, 0, // Arg length + null byte
            97, 98, 0,  // The arg + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("invalid opcode allowed");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            3, 0, 0,    // Arg length + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("truncated data allowed");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            4, 0, 0, 0, // Arg length + null byte (length is too long)
            97, 98, 0,  // The arg + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("long arg length allowed");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            2, 0, 0, 0, // Arg length + null byte (length is too short)
            97, 98, 0,  // The arg + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Operation>>::try_into(&mut bytes.as_slice())
            .expect_err("short arg length allowed");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            3, 0, 0, 0, // Arg length + null byte
            97, 98, 0,  // The arg + null byte
        ];
        let op: Operation = (&mut bytes.as_slice()).try_into()
            .expect("valid bytes not decoded");
        assert_eq!(op, Operation {
            opcode: OpCode::DeleteFile,
            arg: String::from("ab"),
        }, "valid bytes not decoded properly");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            0, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            1, 0, 0, 0, // Arg length + null byte
            0,          // The arg + null byte
        ];
        let op: Operation = (&mut bytes.as_slice()).try_into()
            .expect("empty string not decoded");
        assert_eq!(op, Operation {
            opcode: OpCode::DownloadExe1,
            arg: String::from(""),
        }, "empty string not decoded properly");

        let bytes = [
            0, 0, 0, 0, // Ignored word
            8, 0, 0, 0, // Opcode (le)
            0, 0, 0, 0, // Ignored word
            3, 0, 0, 0, // Arg length + null byte
            97, 98, 0,  // The arg + null byte + bonus byte
            99,         // Bonus byte
        ];
        let op: Operation = (&mut bytes.as_slice()).try_into()
            .expect("bonus bytes not decoded");
        assert_eq!(op, Operation {
            opcode: OpCode::DeleteFile,
            arg: String::from("ab"),
        }, "not decoded properly");
    }

    #[test]
    fn test_response_encoding() {
        let response = Response {
            ops: Vec::new(),
        };
        let bytes: Vec<u8> = response.into();
        assert_eq!(bytes, &[
            8, 0, 0, 0, // Length
            0, 0, 0, 0, // Number of commands
        ], "no-op response not encoded properly");

        let response = Response {
            ops: vec![
                Operation {
                    opcode: OpCode::DeleteFile,
                    arg: String::from("ab"),
                },
                Operation {
                    opcode: OpCode::DownloadExe1,
                    arg: String::from(""),
                },
            ],
        };
        let bytes: Vec<u8> = response.into();
        assert_eq!(bytes, &[
            44, 0, 0, 0,    // Length
            2, 0, 0, 0,     // Number of commands

            0, 0, 0, 0,     // Ignored word
            8, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            3, 0, 0, 0,     // Arg length + null byte
            97, 98, 0,      // The arg + null byte
            
            0, 0, 0, 0,     // Ignored word
            0, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            1, 0, 0, 0,     // Arg length + null byte
            0,              // The arg + null byte
        ], "normal response not encoded properly");
    }

    #[test]
    fn test_response_decoding() {
        let bytes: [u8; 0] = [];
        let _ = <&mut &[u8] as TryInto<Response>>::try_into(&mut bytes.as_slice())
            .expect_err("empty bytes allowed");

        let bytes = [
            8, 0, 0, 0, // Length
            1, 0, 0, 0, // Number of commands
        ];
        let _ = <&mut &[u8] as TryInto<Response>>::try_into(&mut bytes.as_slice())
            .expect_err("long number of commands allowed");

        let bytes = [
            7, 0, 0, 0, // Length
            0, 0, 0,    // Number of commands
        ];
        let _ = <&mut &[u8] as TryInto<Response>>::try_into(&mut bytes.as_slice())
            .expect_err("truncated header allowed");

        let bytes = [
            31, 0, 0, 0,    // Length
            2, 0, 0, 0,     // Number of commands

            0, 0, 0, 0,     // Ignored word
            8, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            3, 0, 0, 0,     // Arg length + null byte
            97, 98, 0,      // The arg + null byte
            
            0, 0, 0, 0,     // Ignored word
        ];
        let _ = <&mut &[u8] as TryInto<Response>>::try_into(&mut bytes.as_slice())
            .expect_err("truncated data allowed");

        let bytes = [
            44, 0, 0, 0,    // Length
            3, 0, 0, 0,     // Number of commands (too long)

            0, 0, 0, 0,     // Ignored word
            8, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            3, 0, 0, 0,     // Arg length + null byte
            97, 98, 0,      // The arg + null byte
            
            0, 0, 0, 0,     // Ignored word
            0, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            1, 0, 0, 0,     // Arg length + null byte
            0,              // The arg + null byte
        ];
        let _ = <&mut &[u8] as TryInto<Response>>::try_into(&mut bytes.as_slice())
            .expect_err("long length allowed");

        let bytes = [
            8, 0, 0, 0, // Length
            0, 0, 0, 0, // Number of commands
        ];
        let response: Response = (&mut bytes.as_slice()).try_into()
            .expect("empty response not decoded");
        assert_eq!(response, Response {
            ops: vec![],
        }, "empty response not decoded properly");

        let bytes = [
            44, 0, 0, 0,    // Length
            2, 0, 0, 0,     // Number of commands

            0, 0, 0, 0,     // Ignored word
            8, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            3, 0, 0, 0,     // Arg length + null byte
            97, 98, 0,      // The arg + null byte
            
            0, 0, 0, 0,     // Ignored word
            0, 0, 0, 0,     // Opcode (le)
            0, 0, 0, 0,     // Ignored word
            1, 0, 0, 0,     // Arg length + null byte
            0,              // The arg + null byte
        ];
        let response: Response = (&mut bytes.as_slice()).try_into()
            .expect("normal response not decoded");
        assert_eq!(response, Response {
            ops: vec![
                Operation {
                    opcode: OpCode::DeleteFile,
                    arg: String::from("ab"),
                },
                Operation {
                    opcode: OpCode::DownloadExe1,
                    arg: String::from(""),
                },
            ],
        }, "normal response not decoded properly");
    }
}
