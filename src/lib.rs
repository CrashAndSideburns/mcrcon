use rand;
use std::convert::TryInto;
use std::io::{Error, Read, Write};
use std::net::TcpStream;

// All of the possible packet types.
#[repr(i32)]
pub enum PacketType {
    AuthFail = -1,
    Response = 0,
    Command = 2,
    Login = 3,
}

// A packet, which can be sent to or received from the server.
#[derive(Debug)]
pub struct Packet {
    size: i32,
    id: i32,
    packet_type: i32,
    pub payload: String,
}

impl Packet {
    // Create a new packet with a given type and payload. size is automatically generated and id is random.
    pub fn new(packet_type: PacketType, payload: String) -> Self {
        Self {
            size: payload.len() as i32 + 10,
            id: rand::random(),
            packet_type: packet_type as i32,
            payload,
        }
    }

    // Send the packet on some writer.
    // This method doesn't need to consume self, but it does since packets should not be reused.
    pub fn send<T: Write>(self, writer: &mut T) -> Result<(), Error> {
        // Write the size i32 as 4 little-endian bytes.
        writer.write(&self.size.to_le_bytes())?;
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
    pub fn receive<T: Read>(reader: &mut T) -> Result<Self, Error> {
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
        let payload = String::from_utf8(payload).unwrap();

        // Read the two null bytes into a dummy buffer to clear the stream.
        reader.read_exact(&mut [0; 2])?;

        Ok(Self {
            size,
            id,
            packet_type,
            payload,
        })
    }
}

pub struct Connection {
    connection: TcpStream,
    logged_in: bool,
}

impl Connection {
    // Create a new connection. All new connections are not logged in.
    pub fn new(connection: TcpStream) -> Self {
        Self {
            connection,
            logged_in: false,
        }
    }

    pub fn login(&mut self, password: String) -> Result<(), Error> {
        // Only go to the effort of attempting to log in if this connection is not already authenticated.
        if self.logged_in {
            Ok(())
        } else {
            // Construct a login packet and send it to the server.
            let packet = Packet::new(PacketType::Login, password);
            packet.send(&mut self.connection)?;

            // Receive the response packet from the server and throw it away to clear the connection.
            // In the future some checks should be implemented to check that this packet is actually a good response.
            Packet::receive(&mut self.connection)?;

            // Set this connection's login status to true.
            self.logged_in = true;
            Ok(())
        }
    }

    pub fn command(&mut self, command: String) -> Result<Packet, Error> {
        // Construct a command packet and send it to the server.
        let packet = Packet::new(PacketType::Command, command);
        packet.send(&mut self.connection)?;

        // Return the response packet from the server.
        Ok(Packet::receive(&mut self.connection)?)
    }
}
