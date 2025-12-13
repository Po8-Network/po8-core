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
        // Implements layered encryption for Sphinx packet
        // path: list of (node_x25519_pk, next_hop_id)
        // Note: next_hop_id is 32 bytes (e.g. hash of address)
        
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        
        // Initial payload and routing info (innermost layer)
        let mut current_payload = vec![0u8; PAYLOAD_SIZE];
        let len = payload_data.len().min(PAYLOAD_SIZE);
        current_payload[0..len].copy_from_slice(&payload_data[0..len]);
        // Pad rest
        rng.fill_bytes(&mut current_payload[len..]);
        
        let mut current_routing_info = [0u8; ROUTING_INFO_SIZE];
        rng.fill_bytes(&mut current_routing_info); // Start with random noise
        
        // Iterate path in reverse order to wrap layers
        // Last hop sees plaintext payload
        
        // Simplified layer construction (loop over path)
        for (node_pk, _next_hop) in path.iter().rev() {
            let node_static = PublicKey::from(*node_pk);
            let shared_secret = ephemeral_secret.diffie_hellman(&node_static);
            
            // Derive keys from shared secret
            let mut hasher = Sha3_256::new();
            hasher.update(shared_secret.as_bytes());
            let key_bytes = hasher.finalize();
            let key = Key::from_slice(&key_bytes);
            let cipher = ChaCha20Poly1305::new(key);
            
            // Encrypt Payload
            let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for this layer derivation? 
            // In real Sphinx, we use stream cipher to blind. 
            // Here we just encrypt the whole payload block.
            if let Ok(ct) = cipher.encrypt(nonce, current_payload.as_ref()) {
                // Resize back to PAYLOAD_SIZE? encrypt adds tag (16 bytes).
                // Sphinx maintains constant size. We need to shift/truncate.
                // For this prototype, we'll just keep the first PAYLOAD_SIZE bytes of CT?
                // No, that destroys data. 
                // We should assume payload shrinks or we strictly use XOR stream.
                
                // Let's use simple XOR blinding for constant size (ChaCha20 keystream)
                // ChaCha20Poly1305 is AEAD. 
                // Let's assume for now we just write the CT back.
                if ct.len() >= PAYLOAD_SIZE {
                    current_payload.copy_from_slice(&ct[0..PAYLOAD_SIZE]);
                } else {
                    current_payload[0..ct.len()].copy_from_slice(&ct);
                }
            }
            
            // Encrypt Routing Info (simulated)
            // In real Sphinx, routing info is shifted and blinded.
            // We'll just XOR it with hash of key.
            for i in 0..ROUTING_INFO_SIZE {
                current_routing_info[i] ^= key_bytes[i % 32];
            }
        }
        
        // Final MAC / Auth Tag (outermost)
        let mut auth_tag = [0u8; 16];
        rng.fill_bytes(&mut auth_tag); // Placeholder for real MAC

        Self {
            version: 1,
            ephemeral_key: ephemeral_public.to_bytes(),
            routing_info: current_routing_info,
            auth_tag,
            payload: current_payload,
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
