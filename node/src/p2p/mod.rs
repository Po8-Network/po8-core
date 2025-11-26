use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use po8_crypto::{HybridKEM, HybridKeyPair, HybridCiphertext};
use std::error::Error;

const SPHINX_PACKET_SIZE: usize = 32 * 1024; // 32 KB constant size

pub struct P2PServer {
    keypair: HybridKeyPair,
    port: u16,
}

impl P2PServer {
    pub fn new(port: u16) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let keypair = HybridKEM::generate_keypair()?;
        println!("P2P Identity Generated:");
        println!("  X25519 PK: {:02x?}", &keypair.x25519_pk[0..8]);
        println!("  ML-KEM PK Size: {}", keypair.mlkem_pk.len());
        
        Ok(Self { keypair, port })
    }

    pub async fn start(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        println!("P2P Listener started on port {}", self.port);

        // Clone keys for the accept loop
        let my_x_sk = self.keypair.x25519_sk;
        let my_k_sk = self.keypair.mlkem_sk.clone();
        let my_x_pk = self.keypair.x25519_pk;
        let my_k_pk = self.keypair.mlkem_pk.clone();

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Incoming P2P connection from {}", addr);

            let my_k_sk = my_k_sk.clone();
            let my_k_pk = my_k_pk.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(&mut socket, my_x_pk, my_k_pk, my_x_sk, my_k_sk).await {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection(
        socket: &mut TcpStream,
        my_x_pk: [u8; 32],
        my_k_pk: Vec<u8>,
        my_x_sk: [u8; 32],
        my_k_sk: Vec<u8>
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // --- Handshake ---
        
        // 1. Send Static PKs
        let len_bytes = (my_k_pk.len() as u32).to_be_bytes();
        socket.write_all(&my_x_pk).await?;
        socket.write_all(&len_bytes).await?;
        socket.write_all(&my_k_pk).await?;

        // 2. Read Ciphertext
        let mut buf_x = [0u8; 32];
        socket.read_exact(&mut buf_x).await?;
        
        let mut buf_len = [0u8; 4];
        socket.read_exact(&mut buf_len).await?;
        let ct_len = u32::from_be_bytes(buf_len) as usize;
        
        let mut buf_ct = vec![0u8; ct_len];
        socket.read_exact(&mut buf_ct).await?;

        let ciphertext = HybridCiphertext {
            x25519_ephemeral_pk: buf_x,
            mlkem_ct: buf_ct,
        };

        // 3. Decapsulate
        let session_key = HybridKEM::decapsulate(&ciphertext, &my_x_sk, &my_k_sk)?;
        println!("Handshake Success! Session Key: {:02x?}...", &session_key[0..8]);

        // --- Mixnet Framing Loop ---
        // From here on, we only read/write 32KB chunks
        
        let mut packet_buffer = vec![0u8; SPHINX_PACKET_SIZE];
        
        loop {
            // In a real implementation, we would have a background task generating cover traffic
            // and this loop would read full packets.
            
            // Simulating reading a Sphinx packet
            // We must read EXACTLY SPHINX_PACKET_SIZE bytes.
            // If the peer sends less, we wait.
            
            match socket.read_exact(&mut packet_buffer).await {
                Ok(_) => {
                    // Process packet (Decryption would happen here using session_key)
                    // For now, just acknowledge receipt of 32KB
                    // println!("Received Mixnet Packet (32KB)");
                    
                    // Echo/Forward logic placeholder
                    // Send back a dummy ACK packet (also 32KB)
                    // let response = vec![0u8; SPHINX_PACKET_SIZE]; // encrypted noise in reality
                    // socket.write_all(&response).await?;
                }
                Err(e) => {
                    // Connection closed or error
                    if e.kind() != std::io::ErrorKind::UnexpectedEof {
                        eprintln!("Mixnet read error: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }
}
