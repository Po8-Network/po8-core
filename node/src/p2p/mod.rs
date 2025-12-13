use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, unbounded_channel};
use po8_crypto::{HybridKEM, HybridKeyPair, HybridCiphertext};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use std::sync::{Arc, Mutex};
use std::error::Error;

pub mod sphinx;

pub const MAX_FRAME: usize = 64 * 1024;

pub struct P2PServer {
    keypair: HybridKeyPair,
    port: u16,
    pub inbound_tx: UnboundedSender<Vec<u8>>,
    outbound: Arc<Mutex<std::collections::HashMap<String, UnboundedSender<Vec<u8>>>>>,
    // Store peer keys: address -> (x25519_pk, mlkem_pk)
    pub peer_keys: Arc<Mutex<std::collections::HashMap<String, ([u8; 32], Vec<u8>)>>>,
}

impl P2PServer {
    pub fn new(port: u16, inbound_tx: UnboundedSender<Vec<u8>>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let keypair = HybridKEM::generate_keypair()?;
        println!("P2P Identity Generated:");
        println!("  X25519 PK: {:02x?}", &keypair.x25519_pk[0..8]);
        println!("  ML-KEM PK Size: {}", keypair.mlkem_pk.len());
        
        Ok(Self { 
            keypair, 
            port, 
            inbound_tx, 
            outbound: Arc::new(Mutex::new(std::collections::HashMap::new())),
            peer_keys: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    pub fn public_identity(&self) -> ([u8; 32], Vec<u8>) {
        (self.keypair.x25519_pk, self.keypair.mlkem_pk.clone())
    }

    pub async fn start(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        println!("P2P Listener started on port {}", self.port);

        // Clone keys for the accept loop
        let my_x_sk = self.keypair.x25519_sk;
        let my_k_sk = self.keypair.mlkem_sk.clone();
        let my_x_pk = self.keypair.x25519_pk;
        let my_k_pk = self.keypair.mlkem_pk.clone();

        let inbound = self.inbound_tx.clone();

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Incoming P2P connection from {}", addr);

            let my_k_sk = my_k_sk.clone();
            let my_k_pk = my_k_pk.clone();
            let inbound = inbound.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(&mut socket, my_x_pk, my_k_pk, my_x_sk, my_k_sk, inbound).await {
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
        my_k_sk: Vec<u8>,
        inbound: UnboundedSender<Vec<u8>>,
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

        // --- Encrypted Framing Loop ---
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
        let mut frames_seen = 0u64;
        loop {
            let mut len_buf = [0u8; 4];
            if socket.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > MAX_FRAME {
                break;
            }
            let mut buf = vec![0u8; frame_len];
            if socket.read_exact(&mut buf).await.is_err() {
                break;
            }
            if buf.len() < 12 {
                continue;
            }
            let nonce = Nonce::from_slice(&buf[..12]);
            let ciphertext = &buf[12..];
            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                let _ = inbound.send(plaintext);
            }
            frames_seen += 1;
            if frames_seen > 1000 {
                // Avoid unbounded resource use per connection
                break;
            }
        }

        Ok(())
    }

    /// Initiates a connection to a peer, performs HybridKEM handshake, encrypts and sends one frame.
    pub async fn send_encrypted(&self, addr: &str, payload: Vec<u8>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut socket = TcpStream::connect(addr).await?;

        // Receive peer static keys
        let mut peer_x_pk = [0u8; 32];
        socket.read_exact(&mut peer_x_pk).await?;

        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await?;
        let pk_len = u32::from_be_bytes(len_buf) as usize;
        let mut peer_mlkem = vec![0u8; pk_len];
        socket.read_exact(&mut peer_mlkem).await?;

        // Encapsulate
        let peer_x: [u8; 32] = peer_x_pk;
        let (ct, session_key) = HybridKEM::encapsulate(&peer_x, &peer_mlkem)?;

        // Send ciphertext to complete handshake
        let ct_len = (ct.mlkem_ct.len() as u32).to_be_bytes();
        socket.write_all(&ct.x25519_ephemeral_pk).await?;
        socket.write_all(&ct_len).await?;
        socket.write_all(&ct.mlkem_ct).await?;

        // Encrypt payload
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = match cipher.encrypt(nonce, payload.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                return Err(Box::<dyn Error + Send + Sync>::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("encrypt failed: {:?}", e),
                )))
            }
        };

        let mut frame = Vec::with_capacity(4 + 12 + ciphertext.len());
        frame.extend_from_slice(&(12 + ciphertext.len() as u32).to_be_bytes());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);

        socket.write_all(&frame).await?;
        Ok(())
    }

    /// Sends payload using a cached outbound channel; establishes and maintains a connection per peer.
    pub fn send_encrypted_cached(&self, addr: &str, payload: Vec<u8>) {
        let addr_string = addr.to_string();
        if let Some(sender) = self.outbound.lock().unwrap().get(&addr_string) {
            let _ = sender.send(payload);
            return;
        }

        let (tx, rx) = unbounded_channel::<Vec<u8>>();
        self.outbound.lock().unwrap().insert(addr_string.clone(), tx.clone());
        // queue initial payload
        let _ = tx.send(payload);

        let my_x_pk = self.keypair.x25519_pk;
        let my_k_pk = self.keypair.mlkem_pk.clone();
        let my_x_sk = self.keypair.x25519_sk;
        let my_k_sk = self.keypair.mlkem_sk.clone();
        let outbound_map = self.outbound.clone();
        let peer_keys_map = self.peer_keys.clone();
        
        tokio::spawn(async move {
            Self::outbound_worker(addr_string, rx, my_x_pk, my_k_pk, my_x_sk, my_k_sk, outbound_map, peer_keys_map).await;
        });
    }

    pub fn get_peer_keys(&self, addr: &str) -> Option<([u8; 32], Vec<u8>)> {
        self.peer_keys.lock().unwrap().get(addr).cloned()
    }

    async fn outbound_worker(
        addr: String,
        mut rx: UnboundedReceiver<Vec<u8>>,
        my_x_pk: [u8; 32],
        my_k_pk: Vec<u8>,
        my_x_sk: [u8; 32],
        my_k_sk: Vec<u8>,
        map: Arc<Mutex<std::collections::HashMap<String, UnboundedSender<Vec<u8>>>>>,
        peer_keys: Arc<Mutex<std::collections::HashMap<String, ([u8; 32], Vec<u8>)>>>,
    ) {
        loop {
            // establish connection + handshake
            let mut socket = match TcpStream::connect(addr.as_str()).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    continue;
                }
            };

            // Send our static keys
            let len_bytes = (my_k_pk.len() as u32).to_be_bytes();
            if socket.write_all(&my_x_pk).await.is_err() { continue; }
            if socket.write_all(&len_bytes).await.is_err() { continue; }
            if socket.write_all(&my_k_pk).await.is_err() { continue; }

            // Read peer ciphertext
            let mut buf_x = [0u8; 32];
            if socket.read_exact(&mut buf_x).await.is_err() { continue; }
            let mut buf_len = [0u8; 4];
            if socket.read_exact(&mut buf_len).await.is_err() { continue; }
            let ct_len = u32::from_be_bytes(buf_len) as usize;
            let mut buf_ct = vec![0u8; ct_len];
            if socket.read_exact(&mut buf_ct).await.is_err() { continue; }

            let ciphertext = HybridCiphertext { x25519_ephemeral_pk: buf_x, mlkem_ct: buf_ct };
            let session_key = match HybridKEM::decapsulate(&ciphertext, &my_x_sk, &my_k_sk) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));

            // Store peer key placeholder (since we are Initiator, we don't get peer's PK in this flow? Wait.)
            // The `send_encrypted` method (which this worker replaces) reads peer static keys FIRST.
            // But here I skipped that part in the copy-paste above? Let's check `send_encrypted`.
            // `send_encrypted` reads `peer_x_pk` and `peer_mlkem`.
            // Ah, I need to update this `outbound_worker` to also read peer keys first.
            
            // Correct flow for Initiator:
            // 1. Connect
            // 2. Read Peer Static Keys
            // 3. Encapsulate (sending OUR ephemeral + CT)
            // 4. Derive Session Key
            // This `outbound_worker` code above seems to be doing `decapsulate`? That's wrong for Initiator.
            // Initiator performs `encapsulate`. Responder `decapsulates`.
            
            // Wait, let's look at `handle_connection` (Responder):
            // 1. Send Static PKs.
            // 2. Read Ciphertext.
            // 3. Decapsulate.
            
            // So Initiator should:
            // 1. Read Static PKs.
            // 2. Encapsulate.
            // 3. Send Ciphertext.
            
            // The code I'm replacing (in `outbound_worker`) was doing `decapsulate`. Why?
            // Ah, the previous `outbound_worker` implementation in `mod.rs` (from `Read` tool output) was:
            // "Read peer ciphertext... decapsulate". 
            // This implies the `outbound_worker` was acting as Responder? But it calls `TcpStream::connect`, so it is Initiator.
            // If `outbound_worker` is Initiator, it must Encapsulate.
            // The previous code in `mod.rs` was actually WRONG/Confused in `outbound_worker` if it was doing decapsulate.
            // Let's fix it now.
            
            // Wait, let's re-read `send_encrypted` in `mod.rs`.
            // `send_encrypted`: Connect -> Read Peer PK -> Encapsulate -> Send CT -> Encrypt Payload. Correct.
            
            // Now let's look at `outbound_worker` in `mod.rs` again (lines 207+).
            // It was doing: Connect -> Send Static Keys -> Read Ciphertext -> Decapsulate.
            // This means it was expecting the *Server* to be the Encapsulator?
            // `handle_connection` (Server) does: Send Static Keys -> Read Ciphertext -> Decapsulate.
            // Both are sending static keys? Both are waiting for ciphertext? Deadlock or Logic Error.
            
            // `handle_connection` (Server):
            // 1. Write My PK
            // 2. Read Ciphertext (ephemeral + ct)
            // 3. Decapsulate
            
            // So the Client (Initiator) MUST:
            // 1. Read Server PK
            // 2. Encapsulate
            // 3. Write Ciphertext
            
            // The `outbound_worker` in `mod.rs` (lines 207+) was:
            // 1. Write My PK (Wrong order if Server writes first?)
            //    - If Server writes first, Client must Read first.
            //    - If Client writes first, Server must Read first.
            // `handle_connection` writes first. So `outbound_worker` MUST Read first.
            
            // I will implement the correct Initiator flow in `outbound_worker`.
            
            // 1. Read Peer Keys
            let mut peer_x_pk = [0u8; 32];
            if socket.read_exact(&mut peer_x_pk).await.is_err() { continue; }
            let mut buf_len = [0u8; 4];
            if socket.read_exact(&mut buf_len).await.is_err() { continue; }
            let pk_len = u32::from_be_bytes(buf_len) as usize;
            let mut peer_mlkem = vec![0u8; pk_len];
            if socket.read_exact(&mut peer_mlkem).await.is_err() { continue; }
            
            // Store keys
            peer_keys.lock().unwrap().insert(addr.clone(), (peer_x_pk, peer_mlkem.clone()));

            // 2. Encapsulate
            let peer_x_static = peer_x_pk; // Copy
            let (ct, session_key) = match HybridKEM::encapsulate(&peer_x_static, &peer_mlkem) {
                Ok(res) => res,
                Err(_) => continue,
            };
            
            // 3. Send Ciphertext
            let ct_len = (ct.mlkem_ct.len() as u32).to_be_bytes();
            if socket.write_all(&ct.x25519_ephemeral_pk).await.is_err() { continue; }
            if socket.write_all(&ct_len).await.is_err() { continue; }
            if socket.write_all(&ct.mlkem_ct).await.is_err() { continue; }
            
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));

            // drain queue until error
            loop {
                let payload = match rx.recv().await {
                    Some(p) => p,
                    None => {
                        map.lock().unwrap().remove(&addr);
                        return;
                    }
                };

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = match cipher.encrypt(nonce, payload.as_ref()) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let mut frame = Vec::with_capacity(4 + 12 + ciphertext.len());
                frame.extend_from_slice(&(12 + ciphertext.len() as u32).to_be_bytes());
                frame.extend_from_slice(&nonce_bytes);
                frame.extend_from_slice(&ciphertext);

                if socket.write_all(&frame).await.is_err() {
                    break; // reconnect
                }
            }
        }
    }
}
