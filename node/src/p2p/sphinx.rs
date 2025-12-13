use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use rand::{Rng, RngCore};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use std::convert::TryInto;

pub const PACKET_SIZE: usize = 32 * 1024; // 32 KB
pub const ROUTING_INFO_SIZE: usize = 1300;
pub const HEADER_SIZE: usize = 1 + 32 + ROUTING_INFO_SIZE + 16; // Version + Ephemeral + Routing + Mac
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

#[derive(Debug, Clone)]
pub struct SphinxPacket {
    pub version: u8,
    pub ephemeral_key: [u8; 32],
    pub routing_info: [u8; ROUTING_INFO_SIZE],
    pub auth_tag: [u8; 16],
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    pub fn new(payload_data: &[u8], path: &[([u8; 32], [u8; 32])]) -> Self {
        // Placeholder for full Sphinx construction
        // Currently implements a simplified layered encryption
        // path: list of (node_public_key, next_hop_id)
        
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        
        // In a real Sphinx, we'd compute shared secrets for each hop
        // and wrap the header and payload in layers.
        // For this prototype, we just init the struct.
        
        let mut routing_info = [0u8; ROUTING_INFO_SIZE];
        rng.fill_bytes(&mut routing_info); // Fill with noise for now
        
        let mut auth_tag = [0u8; 16];
        rng.fill_bytes(&mut auth_tag);

        let mut payload = vec![0u8; PAYLOAD_SIZE];
        let len = payload_data.len().min(PAYLOAD_SIZE);
        payload[0..len].copy_from_slice(&payload_data[0..len]);
        // Pad rest with noise
        rng.fill_bytes(&mut payload[len..]);

        Self {
            version: 1,
            ephemeral_key: ephemeral_public.to_bytes(),
            routing_info,
            auth_tag,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PACKET_SIZE);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&self.routing_info);
        bytes.extend_from_slice(&self.auth_tag);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PACKET_SIZE {
            return None;
        }
        let version = bytes[0];
        let ephemeral_key: [u8; 32] = bytes[1..33].try_into().ok()?;
        let routing_info: [u8; ROUTING_INFO_SIZE] = bytes[33..33+ROUTING_INFO_SIZE].try_into().ok()?;
        let auth_tag: [u8; 16] = bytes[33+ROUTING_INFO_SIZE..33+ROUTING_INFO_SIZE+16].try_into().ok()?;
        let payload = bytes[33+ROUTING_INFO_SIZE+16..].to_vec();

        Some(Self {
            version,
            ephemeral_key,
            routing_info,
            auth_tag,
            payload,
        })
    }
}
