use rand;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::string;
use std::{
    io,
    io::{Read, Write},
};

// Both incoming and outgoing packets have a maximum payload size.
// https://wiki.vg/RCON#Fragmentation
const MAX_INCOMING_PAYLOAD: usize = 4096;
const MAX_OUTGOING_PAYLOAD: usize = 1446;

// Possible errors when using the library.
#[derive(Debug)]
pub enum RCONError {
    // Authenticating a connection failed.
    AuthFail,
    // A packet (either created or received) has a disallowed size.
    // That means either the specified size was above the max allowed size or was negative.
    BadSize(usize),
    // The payload of a packet could not be converted into a valid UTF-8 string.
    BadPayload(string::FromUtf8Error),
    // The ID of a response packet does not match the ID of the sent command.
    IDMismatch,
    // Some kind of IO error, probably failure to read to or write to the connection.
    IO(io::Error),
}

// io::Error needs to be able to be turned into an RCONError.
impl From<io::Error> for RCONError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

// string::FromUtf8Error means that the payload was not a valid UTF-8 string.
impl From<string::FromUtf8Error> for RCONError {
    fn from(error: string::FromUtf8Error) -> Self {
        Self::BadPayload(error)
    }
}

// Display all of our various errors.
impl fmt::Display for RCONError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFail => {
                write!(f, "Authentication failed.")
            }
            Self::BadSize(size) => {
                write!(
                    f,
                    "The size of the supplied payload {} exceeds that maximum payload size of {}",
                    size, MAX_OUTGOING_PAYLOAD
                )
            }
            Self::BadPayload(err) => err.fmt(f),
            Self::IDMismatch => {
                write!(f, "The ID of the packet received from the server does not match the ID of the sent packet.")
            }
            Self::IO(err) => err.fmt(f),
        }
    }
}

// impl Error for our custom error type.
impl Error for RCONError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(err) => Some(err),
            Self::BadPayload(err) => Some(err),
            other => Some(other),
        }
    }
}

// A custom Result type to save the trouble of typing Result<T, RCONError> over and over.
type Result<T> = std::result::Result<T, RCONError>;

// All of the possible packet types. In-memory representation is i32 to simplify packet creation.
#[repr(i32)]
pub enum PacketType {
    AuthFail = -1,
    Response = 0,
    Command = 2,
    Login = 3,
}

// A packet, which can be sent to or received from the server.
// Packets must also include their size, but this is automatically calculated.
#[derive(Debug, PartialEq)]
pub struct Packet {
    id: i32,
    packet_type: i32,
    pub payload: String,
}

impl Packet {
    // Create a new packet with a given type and payload. id is random.
    // Will return Err(PayloadTooLarge) if the length of the payload exceeds 1446 bytes.
    pub fn new(packet_type: PacketType, payload: String) -> Result<Self> {
        if payload.len() <= MAX_OUTGOING_PAYLOAD {
            Ok(Self {
                id: rand::random(),
                packet_type: packet_type as i32,
                payload,
            })
        } else {
            Err(RCONError::BadSize(payload.len()))
        }
    }

    // Calculate the size of a packet, including bytes for id, packet type, and padding.
    // Since payload can be changed after instantiation, check that payload still has a valid length.
    fn size(&self) -> Result<i32> {
        if self.payload.len() <= MAX_OUTGOING_PAYLOAD {
            // The cast from usize to i32 is always safe, since we know here that the payload is at most 1446 bytes.
            Ok(self.payload.len() as i32 + 10)
        } else {
            Err(RCONError::BadSize(self.payload.len()))
        }
    }

    // Construct a copy of the packet that the server will respond with on authentication success.
    fn auth_success_packet(id: i32) -> Self {
        Self {
            id,
            packet_type: PacketType::Command as i32,
            payload: String::from(""),
        }
    }

    // Send the packet on some writer.
    // This method doesn't need to consume self, but it does since packets should not be reused.
    pub fn send<T: Write>(self, writer: &mut T) -> Result<()> {
        // Write the size i32 as 4 little-endian bytes.
        writer.write(&self.size()?.to_le_bytes())?;
        // Write the id i32 as 4 little-endian bytes.
        writer.write(&self.id.to_le_bytes())?;
        // Write the packet type i32 as 4 little-endian bytes.
        writer.write(&self.packet_type.to_le_bytes())?;
        // Write the payload string to the writer as a byte array.
        writer.write(self.payload.as_bytes())?;
        // Write 2 null bytes. One to simulate the payload being null-terminated and one to terminate the packet.
        writer.write(&[0x0, 0x0])?;
        Ok(())
    }

    // Read a packet from some reader.
    pub fn receive<T: Read>(reader: &mut T) -> Result<Self> {
        // Create a 4-byte buffer. This will be used for reading in all i32s.
        let mut buf = [0; 4];

        // Read the first 4 bytes into the buffer. This is the size of the packet as a little-endian i32.
        reader.read_exact(&mut buf)?;
        let size = i32::from_le_bytes(buf);

        // Read the next 4 bytes into the buffer. This is the id of the packet as a little-endian i32.
        reader.read_exact(&mut buf)?;
        let id = i32::from_le_bytes(buf);

        // Read the next 4 bytes into the buffer. This is the type of the packet as a little-endian i32.
        reader.read_exact(&mut buf)?;
        let packet_type = i32::from_le_bytes(buf);

        // Create a Vec to hold the payload. The size of the Vec is size - 10 (8 bytes for the id and type, plus 2 null bytes).
        // Currently this panics if size < 10. This should never be the case, but error handling should be added.
        let mut payload = vec![0; (size - 10).try_into().unwrap()];

        // Read the payload of the packet into the Vec, then convert into a String.
        reader.read_exact(&mut payload)?;
        let payload = String::from_utf8(payload)?;

        // Read the two null bytes into a dummy buffer to clear the stream.
        reader.read_exact(&mut [0; 2])?;

        Ok(Self {
            id,
            packet_type,
            payload,
        })
    }
}

// A struct representing a connection to a Minecraft server.
pub struct Connection<T> {
    connection: T,
}

impl<T: Read + Write> Connection<T> {
    pub fn connect(mut connection: T, password: String) -> Result<Self> {
        // Construct a login packet, save the id, and send it to the server.
        let packet = Packet::new(PacketType::Login, password)?;
        let id = packet.id;
        packet.send(&mut connection)?;
        // If the packet received back from the server indicates authorization succeeded, return an authenticated Connection.
        if Packet::receive(&mut connection)? == Packet::auth_success_packet(id) {
            Ok(Self { connection })
        } else {
            Err(RCONError::AuthFail)
        }
    }

    pub fn command(&mut self, command: String) -> Result<Packet> {
        // Construct a command packet, save the id, and send it to the server.
        let packet = Packet::new(PacketType::Command, command)?;
        let id = packet.id;
        packet.send(&mut self.connection)?;

        // Get a response packet from the server. If the packet's id matches the id of the sent packet, return the response.
        // IDMismatch error if the id's do not match.
        let resp = Packet::receive(&mut self.connection)?;
        if resp.id == id {
            Ok(resp)
        } else {
            Err(RCONError::IDMismatch)
        }
    }
}
