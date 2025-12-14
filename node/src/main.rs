use po8_crypto::{MlDsa65, QuantumSigner};
use po8_consensus::{ConsensusEngine, compute_block_hash, compute_txs_merkle, derive_address};
use po8_vm::EvmEngine;
use std::sync::{Arc, Mutex};
use warp::Filter;
use std::env;
use sha3::{Digest, Sha3_256};
use base64::{engine::general_purpose, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use rand::RngCore;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Serialize, Deserialize};

mod p2p; // Import P2P module
use p2p::sphinx::SphinxPacket; // Import Sphinx Packet

#[derive(serde::Deserialize)]
struct RpcRequest {
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

fn forward_to_peers(peers: Arc<Vec<String>>, packet: Vec<u8>, p2p: Arc<p2p::P2PServer>) {
    for peer in peers.iter() {
        let peer_addr = peer.clone();
        let data = packet.clone();
        let p2p = p2p.clone();
        p2p.send_encrypted_cached(&peer_addr, data);
    }
}

fn pad_packet(data: &[u8]) -> Option<Vec<u8>> {
    // If it's already a Sphinx packet (32KB), just return it
    if data.len() == p2p::sphinx::PACKET_SIZE {
        return Some(data.to_vec());
    }
    
    // Legacy padding for non-Sphinx frames
    if data.len() + 4 > MAX_PACKET {
        return None;
    }
    let mut pkt = vec![0u8; MAX_PACKET];
    let len = data.len() as u32;
    pkt[0..4].copy_from_slice(&len.to_be_bytes());
    pkt[4..4 + data.len()].copy_from_slice(data);
    Some(pkt)
}

fn parse_relay(packet: &[u8]) -> Option<RelayPacket> {
    if packet.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if len > packet.len().saturating_sub(4) {
        return None;
    }
    serde_json::from_slice::<RelayPacket>(&packet[4..4 + len]).ok()
}

// Deprecated JSON OnionFrame parser (kept for backward compat if needed, but we prefer SphinxPacket)
fn parse_onion(packet: &[u8]) -> Option<OnionFrame> {
    if packet.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if len > packet.len().saturating_sub(4) {
        return None;
    }
    serde_json::from_slice::<OnionFrame>(&packet[4..4 + len]).ok()
}

fn handle_sphinx(packet: SphinxPacket, messages: &Arc<Mutex<MessageStore>>, peers: &Arc<Vec<String>>, p2p: &Arc<p2p::P2PServer>) {
    // In a real Sphinx implementation, we would:
    // 1. Perform ECDH with our static key and the packet's ephemeral key.
    // 2. Derive shared secret and unwrap one layer of encryption.
    // 3. Check routing info to see if we are the destination.
    
    // For this prototype/integration:
    // We assume we are the destination or a hop.
    // Since we don't have the full unwrapping logic wired to the P2PServer's static key in this scope easily,
    // we will check if the payload inside looks like a RelayPacket.
    
    // Attempt to parse payload as RelayPacket directly (simulating successful unwrap at final hop)
    // The payload is padded. We need to find the length prefix.
    
    if let Some(relay) = parse_relay(&packet.payload) {
        process_relay(relay, messages, peers, p2p);
    } else {
        // If not a relay packet, it might be a forwardable Sphinx packet for someone else.
        // Simplified forwarding: pick a random peer and forward (mixnet behavior)
        let next_hop = peers.choose(&mut thread_rng());
        if let Some(peer) = next_hop {
            forward_to_peer(peer, packet.to_bytes(), p2p.clone());
        }
    }
}

fn handle_onion(frame: OnionFrame, messages: &Arc<Mutex<MessageStore>>, peers: &Arc<Vec<String>>, p2p: &Arc<p2p::P2PServer>) {
    let hop = frame.hop;
    if hop >= frame.path.len() {
        return;
    }

    let next_hop = frame.path[hop].clone();
    let final_hop = hop + 1 >= frame.path.len();

    if next_hop == "local" || final_hop {
        if let Ok(inner) = general_purpose::STANDARD.decode(&frame.payload_b64) {
            if !verify_checksum(&inner, &frame.checksum) {
                return;
            }
            if let Some(relay) = parse_relay(&pad_for_inner(&inner)) {
                process_relay(relay, messages, peers, p2p);
            }
        }
        return;
    }

    let mut new_frame = frame.clone();
    new_frame.hop = hop + 1;
    if let Ok(bytes) = serde_json::to_vec(&new_frame) {
        if let Some(pkt) = pad_packet(&bytes) {
            forward_to_peer(&next_hop, pkt, p2p.clone());
        }
    }
}

fn pad_for_inner(inner: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + inner.len());
    buf.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    buf.extend_from_slice(inner);
    buf
}

fn verify_checksum(data: &[u8], checksum_hex: &str) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize()) == checksum_hex
}

fn forward_to_peer(peer_addr: &str, packet: Vec<u8>, p2p: Arc<p2p::P2PServer>) {
    let addr = peer_addr.to_string();
    p2p.send_encrypted_cached(&addr, packet);
}

fn build_path(peers: &Arc<Vec<String>>) -> Vec<String> {
    let mut rng = thread_rng();
    let mut selection: Vec<String> = peers.as_ref().clone();
    selection.shuffle(&mut rng);
    let mut path: Vec<String> = selection.into_iter().take(2).collect();
    path.push("local".to_string());
    path
}

fn process_relay(relay: RelayPacket, messages: &Arc<Mutex<MessageStore>>, peers: &Arc<Vec<String>>, p2p: &Arc<p2p::P2PServer>) {
    let RelayPacket { recipient, sender_pk, signature, payload, nonce, ttl, kind, ack_for } = relay;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if ttl == 0 || ttl > 900 {
        return;
    }
    let expiry = now + ttl;

    if let (Ok(pk_bytes), Ok(sig_bytes), Ok(payload_bytes)) = (
        hex::decode(&sender_pk),
        hex::decode(&signature),
        general_purpose::STANDARD.decode(&payload)
    ) {
        if payload_bytes.len() > MAX_PACKET {
            return;
        }
        let mut msg_bytes = recipient.as_bytes().to_vec();
        msg_bytes.extend_from_slice(&payload_bytes);
        if let Ok(valid) = MlDsa65::verify(&msg_bytes, &sig_bytes, &pk_bytes) {
            if !valid {
                return;
            }
        } else {
            return;
        }

        let mut lock = messages.lock().unwrap();
        let id = format!("{}:{}", sender_pk, nonce);
        if lock.seen.contains(&id) {
            return;
        }
        lock.seen.insert(id.clone());

        let envelope = MessageEnvelope {
            sender_pk: sender_pk.clone(),
            payload_b64: payload.clone(),
            timestamp: now,
            nonce,
            expiry,
            kind: kind.clone(),
            ack_for: ack_for.clone(),
        };
        let inbox = lock.inbox.entry(recipient.clone()).or_default();
        if inbox.len() > 200 {
            inbox.remove(0);
        }
        inbox.push(envelope);

        // simple forward (broadcast) to peers to propagate further
        if !peers.is_empty() && ttl > 1 {
            let fwd_ttl = ttl - 1;
            let forward = RelayPacket {
                recipient,
                sender_pk,
                signature,
                payload,
                nonce,
                ttl: fwd_ttl,
                kind,
                ack_for,
            };
            if let Ok(bytes) = serde_json::to_vec(&forward) {
                // Try to use Sphinx packet for forwarding if possible, else legacy
                // For now, wrapping in legacy pad_packet for broadcast
                if let Some(pkt) = pad_packet(&bytes) {
                    forward_to_peers(peers.clone(), pkt, p2p.clone());
                }
            }
        }
    }
}

#[derive(serde::Serialize)]
struct RpcError {
    code: i32,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct RpcResponse {
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
    id: u64,
}

#[derive(Clone, Copy, Debug)]
enum Network {
    Development,
    Testnet,
    Mainnet,
}

impl Network {
    fn chain_id(&self) -> u32 {
        match self {
            Network::Development => 1337,
            Network::Testnet => 80001,
            Network::Mainnet => 8,
        }
    }
}

// Simple store for mining statistics
struct MiningStore {
    blocks_mined: u64,
    total_earnings: u64,
    hash_rate: u64, // hashes per second (simulated)
    miner_address: String,
    is_mining: bool,
}

#[derive(Serialize, Deserialize)]
struct ReceiptStore {
    receipts: std::collections::HashMap<String, serde_json::Value>,
}

impl ReceiptStore {
    fn load_from_disk(path: &str) -> Self {
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(store) = serde_json::from_reader::<_, ReceiptStore>(file) {
                return store;
            }
        }
        ReceiptStore { receipts: std::collections::HashMap::new() }
    }

    fn save_to_disk(&self, path: &str) {
        // Write atomically via temp file + rename
        if let Ok(tmp) = tempfile::NamedTempFile::new() {
            if serde_json::to_writer_pretty(&tmp, self).is_ok() {
                let _ = tmp.persist(path);
            }
        }
    }

    fn clear_stale(&mut self, valid_hashes: &std::collections::HashSet<String>) {
        self.receipts.retain(|k, _| valid_hashes.contains(k));
    }
}

#[derive(Serialize, Deserialize)]
struct Mempool {
    pending_txs: Vec<QuantumTransaction>,
    next_nonce: std::collections::HashMap<String, u64>,
}

impl Mempool {
    fn load_from_disk(path: &str) -> Self {
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(store) = serde_json::from_reader::<_, Mempool>(file) {
                return store;
            }
        }
        Mempool { pending_txs: Vec::new(), next_nonce: std::collections::HashMap::new() }
    }

    fn save_to_disk(&self, path: &str) {
        if let Ok(tmp) = tempfile::NamedTempFile::new() {
            if serde_json::to_writer_pretty(&tmp, self).is_ok() {
                let _ = tmp.persist(path);
            }
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct MessageEnvelope {
    sender_pk: String,
    payload_b64: String,
    timestamp: u64,
    nonce: u64,
    expiry: u64,
    kind: String,
    ack_for: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct RelayPacket {
    recipient: String,
    sender_pk: String,
    signature: String,
    payload: String,
    nonce: u64,
    ttl: u64,
    kind: String,
    ack_for: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct OnionFrame {
    path: Vec<String>,      // sequence of peer addresses; last hop should be "local"
    hop: usize,             // current hop index
    payload_b64: String,    // base64-encoded inner RelayPacket bytes
    checksum: String,       // sha3-256 hex of payload bytes
}

struct MessageStore {
    inbox: HashMap<String, Vec<MessageEnvelope>>,
    seen: HashSet<String>,
    rate_window: HashMap<String, (u64, u32)>, // sender -> (window_start, count)
}

const MAX_PACKET: usize = 32 * 1024;
const MIN_FEE_WEI: u128 = 1; // minimal fee requirement

// Define Quantum Transaction structure for deserialization
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
struct QuantumTransaction {
    sender_pk: String, // Hex encoded ML-DSA-65 Public Key
    recipient: String, // Hex encoded 20-byte address
    amount: String,    // String number
    nonce: u64,
    signature: String, // Hex encoded ML-DSA-65 Signature
    #[serde(default)]
    data: Option<String>, // Hex encoded data (optional)
}

#[tokio::main]
async fn main() {
    // Detect Network Mode
    let network_env = env::var("PO8_NETWORK").unwrap_or_else(|_| "development".to_string());
    let network = match network_env.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        _ => Network::Development,
    };

    println!("Starting Po8 Node on Network: {:?} (ChainID: {})", network, network.chain_id());

    // Initialize Identity
    let keypair = MlDsa65::generate_keypair().unwrap();
    println!("Node Identity (ML-DSA-65 Public Key size: {} bytes)", keypair.public_key.len());

    // Derive Address: keccak256(pk)[0..20] with 0x prefix
    let address = derive_address(&keypair.public_key);
    println!("Miner Address: {}", address);

    let (p2p_tx, mut p2p_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let p2p_port: u16 = env::var("PO8_P2P_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8834);
    let rpc_port: u16 = env::var("PO8_RPC_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8833);

    // Initialize P2P Server (identity needed for messaging RPC)
    let p2p_server = match p2p::P2PServer::new(p2p_port, p2p_tx.clone()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Failed to start P2P server: {}", e);
            return;
        }
    };

    let (mix_x25519_pk, mix_mlkem_pk) = p2p_server.public_identity();
    let mix_identity = Arc::new(serde_json::json!({
        "x25519_pk": hex::encode(mix_x25519_pk),
        "mlkem_pk": hex::encode(mix_mlkem_pk)
    }));

    {
        let p2p_clone = p2p_server.clone();
        tokio::spawn(async move {
            if let Err(e) = p2p_clone.start().await {
                eprintln!("P2P Server Error: {}", e);
            }
        });
    }

    // Known peers for forwarding
    let peers: Arc<Vec<String>> = Arc::new(
        env::var("PO8_PEERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    );
    let peers_rpc = peers.clone();

    // Cover traffic loop (best-effort, encrypted noise)
    {
        let peers = peers.clone();
        let p2p = p2p_server.clone();
        let cover_hz = env::var("PO8_COVER_HZ").ok().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.5);
        let cover_jitter = env::var("PO8_COVER_JITTER").ok().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.3);
        tokio::spawn(async move {
            if peers.is_empty() || cover_hz <= 0.0 {
                return;
            }
            let base_interval = 1.0 / cover_hz.max(0.01);
            loop {
                let mut noise = vec![0u8; 64];
                let _ = rand::thread_rng().fill_bytes(&mut noise);
                // Create Sphinx packet with noise payload
                // For cover traffic, we can just send random bytes if peers drop invalid packets,
                // but better to send valid-looking Sphinx packets.
                let sphinx = SphinxPacket::new(&noise, &[]); 
                let pkt = sphinx.to_bytes();
                
                forward_to_peers(peers.clone(), pkt, p2p.clone());
                
                let jitter = 1.0 + ((rand::random::<f64>() - 0.5) * 2.0 * cover_jitter).clamp(-0.9, 0.9);
                let sleep_ms = (base_interval * jitter * 1000.0).max(100.0) as u64;
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
            }
        });
    }

    // Initialize Stores
    let mut consensus_engine = ConsensusEngine::load_from_disk("po8_chain.json").unwrap_or_else(|_| {
        let mut eng = ConsensusEngine::new();
        eng
    });
    // Register self as validator (Genesis validator) if not present
    if !consensus_engine.validators.contains_key(&address) {
        consensus_engine.add_validator(keypair.public_key.clone(), 100);
    }
    
    let engine = Arc::new(Mutex::new(consensus_engine));
    
    // Initialize EVM
    let mut evm_engine = EvmEngine::load_from_disk("po8_evm_db.json").unwrap_or_else(|e| {
        println!("Could not load EVM DB: {}, starting fresh.", e);
        EvmEngine::new()
    });

    // Mint initial funds to miner for testing
    // Check if miner already has balance, otherwise mint
    if let Ok(bal) = evm_engine.get_balance(address.clone()) {
        if bal == 0 {
             if let Err(e) = evm_engine.mint(address.clone(), 1000_000_000_000_000_000_000) { // 1000 ETH/PO8
                 eprintln!("Failed to mint genesis funds: {}", e);
             } else {
                 let _ = evm_engine.save_to_disk("po8_evm_db.json");
             }
        }
    } else {
         if let Err(e) = evm_engine.mint(address.clone(), 1000_000_000_000_000_000_000) { // 1000 ETH/PO8
             eprintln!("Failed to mint genesis funds: {}", e);
         } else {
             let _ = evm_engine.save_to_disk("po8_evm_db.json");
         }
    }
    
    let vm = Arc::new(Mutex::new(evm_engine));

    let mining_store = Arc::new(Mutex::new(MiningStore {
        blocks_mined: 0,
        total_earnings: 0,
        hash_rate: 0,
        miner_address: format!("0x{}", address),
        is_mining: true, // Auto-start mining
    }));

    let receipt_store = Arc::new(Mutex::new(ReceiptStore::load_from_disk("po8_receipts.json")));

    let mempool = Arc::new(Mutex::new(Mempool::load_from_disk("po8_mempool.json")));

    let message_store = Arc::new(Mutex::new(MessageStore {
        inbox: HashMap::new(),
        seen: HashSet::new(),
        rate_window: HashMap::new(),
    }));

    // Clean receipts for chain continuity
    {
        let engine_lock = engine.lock().unwrap();
        let mut r_lock = receipt_store.lock().unwrap();
        let mut valid = std::collections::HashSet::new();
        for blk in &engine_lock.chain {
            for raw_tx in &blk.txs {
                if let Ok(qtx) = serde_json::from_slice::<QuantumTransaction>(raw_tx) {
                    let mut h = Sha3_256::new();
                    h.update(qtx.sender_pk.as_bytes());
                    h.update(qtx.recipient.as_bytes());
                    h.update(qtx.amount.as_bytes());
                    h.update(qtx.nonce.to_be_bytes());
                    h.update(qtx.signature.as_bytes());
                    valid.insert(format!("0x{}", hex::encode(h.finalize())));
                }
            }
        }
        r_lock.clear_stale(&valid);
        r_lock.save_to_disk("po8_receipts.json");
    }

    let engine_filter = {
        let engine = engine.clone();
        warp::any().map(move || engine.clone())
    };

    let vm_filter = {
        let vm = vm.clone();
        warp::any().map(move || vm.clone())
    };

    let mining_filter = {
        let mining = mining_store.clone();
        warp::any().map(move || mining.clone())
    };

    let receipt_filter = {
        let receipt = receipt_store.clone();
        warp::any().map(move || receipt.clone())
    };

    let mempool_filter = {
        let mempool = mempool.clone();
        warp::any().map(move || mempool.clone())
    };

    let message_filter = {
        let messages = message_store.clone();
        warp::any().map(move || messages.clone())
    };

    let mix_identity_filter = {
        let identity = mix_identity.clone();
        warp::any().map(move || identity.clone())
    };


    // CORS
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["POST", "GET"]);

    // Dashboard Route (Serve Static Files)
    let dashboard_route = warp::get()
        .and(warp::fs::dir("../po8-core/node-dashboard/dist"));

    let p2p_rpc = p2p_server.clone();

    // JSON-RPC Route
    let rpc_route = warp::post()
        .and(warp::path("rpc"))
        .and(warp::body::json())
        .and(engine_filter)
        .and(vm_filter)
        .and(mining_filter)
        .and(receipt_filter)
        .and(mempool_filter)
        .and(message_filter)
        .and(mix_identity_filter)
        .map(move |req: RpcRequest, engine: Arc<Mutex<ConsensusEngine>>, vm: Arc<Mutex<EvmEngine>>, mining: Arc<Mutex<MiningStore>>, receipts: Arc<Mutex<ReceiptStore>>, mempool: Arc<Mutex<Mempool>>, messages: Arc<Mutex<MessageStore>>, mix_identity: Arc<serde_json::Value>| {
            let p2p_server = p2p_rpc.clone();
            let mut response = RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
                id: req.id,
            };

            let make_err = |code: i32, msg: String| -> Option<RpcError> {
                Some(RpcError { code, message: msg, data: None })
            };

            match req.method.as_str() {
                "net_version" => {
                    response.result = Some(serde_json::json!(network.chain_id()));
                },
                "eth_chainId" => {
                    response.result = Some(serde_json::json!(format!("0x{:x}", network.chain_id())));
                },
                "eth_gasPrice" => {
                    response.result = Some(serde_json::json!("0x1"));
                },
                "eth_syncing" => {
                    response.result = Some(serde_json::json!(false));
                },
                "eth_coinbase" => {
                    let lock = mining.lock().unwrap();
                    response.result = Some(serde_json::json!(lock.miner_address));
                },
                "eth_mining" => {
                    let lock = mining.lock().unwrap();
                    response.result = Some(serde_json::json!(lock.is_mining));
                },
                "eth_hashrate" => {
                    let lock = mining.lock().unwrap();
                    response.result = Some(serde_json::json!(format!("0x{:x}", lock.hash_rate)));
                },
                "eth_getTransactionCount" => {
                    let addr = req.params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0").to_string();
                    let m_lock = mempool.lock().unwrap();
                    let next = m_lock.next_nonce.get(&addr).copied().unwrap_or(0);
                    response.result = Some(serde_json::json!(format!("0x{:x}", next)));
                },
                "eth_getCode" => {
                    let addr = req.params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0").to_string();
                    let vm_lock = vm.lock().unwrap();
                    match vm_lock.get_code(addr) {
                        Ok(code) => response.result = Some(serde_json::json!(format!("0x{}", hex::encode(code)))),
                        Err(e) => response.error = make_err(-32000, e),
                    }
                },
                "eth_call" => {
                    if let Some(call_obj) = req.params.get(0).and_then(|v| v.as_object()) {
                         let to = call_obj.get("to").and_then(|v| v.as_str()).unwrap_or("0x").to_string();
                         let from = call_obj.get("from").and_then(|v| v.as_str()).unwrap_or("0x0000000000000000000000000000000000000000").to_string();
                         let data_str = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("").replace("0x", "");
                         let value_str = call_obj.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
                         
                         let value_wei = if value_str.starts_with("0x") {
                             u128::from_str_radix(&value_str[2..], 16).unwrap_or(0)
                         } else {
                             value_str.parse().unwrap_or(0)
                         };
                         
                         let data = hex::decode(data_str).unwrap_or_default();
                         
                         let mut lock = vm.lock().unwrap();
                         match lock.call(from, to, value_wei, data) {
                             Ok(res) => response.result = Some(serde_json::json!(format!("0x{}", res))),
                             Err(e) => response.error = make_err(-32000, e),
                         }
                    } else {
                        response.error = make_err(-32602, "Invalid params for eth_call".to_string());
                    }
                },
                "eth_estimateGas" => {
                     if let Some(call_obj) = req.params.get(0).and_then(|v| v.as_object()) {
                         let to = call_obj.get("to").and_then(|v| v.as_str()).unwrap_or("0x").to_string();
                         let from = call_obj.get("from").and_then(|v| v.as_str()).unwrap_or("0x0000000000000000000000000000000000000000").to_string();
                         let data_str = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("").replace("0x", "");
                         let value_str = call_obj.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
                         
                         let value_wei = if value_str.starts_with("0x") {
                             u128::from_str_radix(&value_str[2..], 16).unwrap_or(0)
                         } else {
                             value_str.parse().unwrap_or(0)
                         };
                         
                         let data = hex::decode(data_str).unwrap_or_default();
                         
                         let mut lock = vm.lock().unwrap();
                         match lock.estimate_gas(from, to, value_wei, data) {
                             Ok(gas) => response.result = Some(serde_json::json!(format!("0x{:x}", gas))),
                             Err(e) => response.error = make_err(-32000, e),
                         }
                     } else {
                         response.result = Some(serde_json::json!("0x5208"));
                     }
                },
                "get_block_count" | "eth_blockNumber" => {
                    let lock = engine.lock().unwrap();
                    response.result = Some(serde_json::json!(format!("0x{:x}", lock.chain.len())));
                },
                "get_balance" | "eth_getBalance" => {
                    let addr = if let Some(a) = req.params.get(0).and_then(|v| v.as_str()) {
                        a.to_string()
                    } else {
                        "0x0000000000000000000000000000000000000000".to_string()
                    };

                    let lock = vm.lock().unwrap();
                    match lock.get_balance(addr) {
                        Ok(bal) => response.result = Some(serde_json::json!(format!("0x{:x}", bal))),
                        Err(e) => response.error = make_err(-32000, e),
                    }
                },
                "get_mix_identity" => {
                    response.result = Some((*mix_identity).clone());
                },
                "mix_send" => {
                    if let Some(obj) = req.params.get(0).and_then(|v| v.as_object()) {
                        let recipient = obj.get("recipient").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let sender_pk_hex = obj.get("sender_pk").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let sig_hex = obj.get("signature").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let payload_b64 = obj.get("payload").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let nonce = obj.get("nonce").and_then(|v| v.as_u64()).unwrap_or_else(|| {
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
                        });
                        let ttl = obj.get("ttl").and_then(|v| v.as_u64()).unwrap_or(300);
                        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("msg").to_string();
                        let ack_for = obj.get("ack_for").and_then(|v| v.as_str()).map(|s| s.to_string());

                        if recipient.is_empty() || sender_pk_hex.is_empty() || sig_hex.is_empty() || payload_b64.is_empty() {
                            response.error = make_err(-32602, "Invalid params".to_string());
                        } else {
                            if let (Ok(pk_bytes), Ok(sig_bytes), Ok(payload_bytes)) = (
                                hex::decode(&sender_pk_hex),
                                hex::decode(&sig_hex),
                                general_purpose::STANDARD.decode(&payload_b64)
                            ) {
                                if payload_bytes.len() > MAX_PACKET {
                                    response.error = make_err(-32000, "Payload too large".to_string());
                                } else {
                                    let mut msg_bytes = recipient.as_bytes().to_vec();
                                    msg_bytes.extend_from_slice(&payload_bytes);
                                    if let Ok(valid) = MlDsa65::verify(&msg_bytes, &sig_bytes, &pk_bytes) {
                                        if valid {
                                            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                                            let expiry = now + ttl.min(900);
                                            let id = format!("{}:{}", sender_pk_hex, nonce);

                                            let mut lock = messages.lock().unwrap();

                                            let duplicate = lock.seen.contains(&id);
                                            let entry = lock.rate_window.entry(sender_pk_hex.clone()).or_insert((now, 0));
                                            if now.saturating_sub(entry.0) >= 60 {
                                                entry.0 = now;
                                                entry.1 = 0;
                                            }

                                            if entry.1 > 30 {
                                                response.error = make_err(-32000, "Rate limited".to_string());
                                            } else if duplicate {
                                                response.result = Some(serde_json::json!("duplicate"));
                                            } else {
                                                entry.1 += 1;
                                                lock.seen.insert(id.clone());
                                                
                                                // Create Relay Packet
                                                let relay = RelayPacket {
                                                    recipient: recipient.clone(),
                                                    sender_pk: sender_pk_hex.clone(),
                                                    signature: sig_hex.clone(),
                                                    payload: payload_b64.clone(),
                                                    nonce,
                                                    ttl,
                                                    kind: kind.clone(),
                                                    ack_for: ack_for.clone(),
                                                };

                                                // Store locally
                                                let envelope = MessageEnvelope {
                                                    sender_pk: sender_pk_hex.clone(),
                                                    payload_b64: payload_b64.clone(),
                                                    timestamp: now,
                                                    nonce,
                                                    expiry,
                                                    kind: kind.clone(),
                                                    ack_for: ack_for.clone(),
                                                };
                                                let inbox = lock.inbox.entry(recipient.clone()).or_default();
                                                if inbox.len() > 200 {
                                                    inbox.remove(0);
                                                }
                                                inbox.push(envelope);
                                                response.result = Some(serde_json::json!("queued"));

                                                // Forward as Sphinx Packet
                                                if !peers_rpc.is_empty() {
                                                    if let Ok(relay_bytes) = serde_json::to_vec(&relay) {
                                                        // Pad to fixed inner size
                                                        if let Some(padded) = pad_for_inner(&relay_bytes).get(0..) {
                                                            let path_addrs = build_path(&peers_rpc);
                                                            // TODO: Lookup public keys for path_addrs from p2p_server
                                                            // For now, using empty path keys (simulated onion)
                                                            let path_keys: Vec<([u8; 32], [u8; 32])> = vec![];
                                                            
                                                            let sphinx = SphinxPacket::new(&pad_for_inner(&relay_bytes), &path_keys);
                                                            let pkt = sphinx.to_bytes();
                                                            
                                                            // Send to first hop
                                                            if !path_addrs.is_empty() {
                                                                forward_to_peer(&path_addrs[0], pkt, p2p_server.clone());
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            response.error = make_err(-32000, "Invalid signature".to_string());
                                        }
                                    } else {
                                        response.error = make_err(-32000, "Signature verification error".to_string());
                                    }
                                }
                            } else {
                                response.error = make_err(-32000, "Decode error".to_string());
                            }
                        }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "mix_poll" => {
                    if let Some(obj) = req.params.get(0).and_then(|v| v.as_object()) {
                        let recipient = obj.get("recipient").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let pk_hex = obj.get("public_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let sig_hex = obj.get("signature").and_then(|v| v.as_str()).unwrap_or("").to_string();

                        if recipient.is_empty() || pk_hex.is_empty() || sig_hex.is_empty() {
                            response.error = make_err(-32602, "Invalid params".to_string());
                        } else {
                            if let (Ok(pk_bytes), Ok(sig_bytes)) = (hex::decode(&pk_hex), hex::decode(&sig_hex)) {
                                let mut msg_bytes = b"poll:".to_vec();
                                msg_bytes.extend_from_slice(recipient.as_bytes());

                                if let Ok(valid) = MlDsa65::verify(&msg_bytes, &sig_bytes, &pk_bytes) {
                                    if valid {
                                        let mut lock = messages.lock().unwrap();
                                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                                        let mut msgs = lock.inbox.remove(&recipient).unwrap_or_default();
                                        msgs.retain(|m| m.expiry >= now);
                                        response.result = Some(serde_json::to_value(msgs).unwrap_or(serde_json::Value::Null));
                                    } else {
                                        response.error = make_err(-32000, "Invalid signature".to_string());
                                    }
                                } else {
                                    response.error = make_err(-32000, "Signature verification error".to_string());
                                }
                            } else {
                                response.error = make_err(-32000, "Decode error".to_string());
                            }
                        }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "get_history" => {
                    response.result = Some(serde_json::json!([]));
                },
                "get_mining_stats" => {
                     let lock = mining.lock().unwrap();
                     response.result = Some(serde_json::json!({
                         "blocks_mined": lock.blocks_mined,
                         "total_earnings": lock.total_earnings,
                         "hash_rate": lock.hash_rate,
                         "miner_address": lock.miner_address,
                         "is_mining": lock.is_mining
                     }));
                },
                "start_mining" => {
                    let mut lock = mining.lock().unwrap();
                    lock.is_mining = true;
                    response.result = Some(serde_json::json!("Mining started"));
                },
                "stop_mining" => {
                    let mut lock = mining.lock().unwrap();
                    lock.is_mining = false;
                    lock.hash_rate = 0;
                    response.result = Some(serde_json::json!("Mining stopped"));
                },
                "get_network_info" => {
                    let lock = engine.lock().unwrap();
                    response.result = Some(serde_json::json!({
                        "network_hashrate": "50.5 MH/s",
                        "difficulty": "0x12345",
                        "peer_count": 8,
                        "block_height": lock.chain.len()
                    }));
                },
                "get_recent_blocks" => {
                    let lock = engine.lock().unwrap();
                    let count = lock.chain.len();
                    let start = if count > 10 { count - 10 } else { 0 };
                    let recent: Vec<_> = lock.chain[start..].iter().rev().collect();
                    response.result = Some(serde_json::json!(recent));
                },
                "get_block_by_height" => {
                    if let Some(height) = req.params.get(0).and_then(|v| v.as_u64()) {
                        let lock = engine.lock().unwrap();
                        if let Some(block) = lock.chain.get(height as usize) {
                            let mut block_json = serde_json::to_value(block).unwrap();
                            if let Some(obj) = block_json.as_object_mut() {
                                if let Some(txs_arr) = obj.get_mut("txs").and_then(|v| v.as_array_mut()) {
                                    let mut decoded_txs = Vec::new();
                                    for tx_bytes_val in txs_arr.iter() {
                                        if let Some(bytes) = serde_json::from_value::<Vec<u8>>(tx_bytes_val.clone()).ok() {
                                             if let Ok(qtx) = serde_json::from_slice::<QuantumTransaction>(&bytes) {
                                                 decoded_txs.push(serde_json::to_value(qtx).unwrap());
                                             }
                                        }
                                    }
                                    *txs_arr = decoded_txs;
                                }
                            }
                            response.result = Some(block_json);
                        } else {
                            response.error = make_err(-32000, "Block not found".to_string());
                        }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "get_fee_estimates" => {
                    response.result = Some(serde_json::json!({
                        "base_fee": "0.000000001",
                        "priority_fee": "0.000000001",
                        "estimated_cost": "0.001"
                    }));
                },
                "eth_getTransactionReceipt" => {
                    if let Some(tx_hash) = req.params.get(0).and_then(|v| v.as_str()) {
                         let lock = receipts.lock().unwrap();
                         if let Some(receipt) = lock.receipts.get(tx_hash) {
                             response.result = Some(receipt.clone());
                         } else {
                             response.result = Some(serde_json::Value::Null);
                         }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "eth_getTransactionByHash" => {
                    if let Some(tx_hash) = req.params.get(0).and_then(|v| v.as_str()) {
                        let r_lock = receipts.lock().unwrap();
                        if let Some(receipt) = r_lock.receipts.get(tx_hash) {
                            let tx_obj = serde_json::json!({
                                "hash": tx_hash,
                                "blockHash": receipt.get("blockHash").cloned().unwrap_or(serde_json::Value::Null),
                                "blockNumber": receipt.get("blockNumber").cloned().unwrap_or(serde_json::Value::Null),
                                "transactionIndex": receipt.get("transactionIndex").cloned().unwrap_or(serde_json::Value::Null),
                            });
                            response.result = Some(tx_obj);
                        } else {
                            response.result = Some(serde_json::Value::Null);
                        }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "eth_getBlockByNumber" | "eth_getBlockByHash" => {
                    if let Some(num_param) = req.params.get(0) {
                        let (height_opt, hash_opt) = match req.method.as_str() {
                            "eth_getBlockByNumber" => {
                                let h = if let Some(s) = num_param.as_str() {
                                    if s == "latest" {
                                        None
                                    } else if s.starts_with("0x") {
                                        u64::from_str_radix(&s[2..], 16).ok()
                                    } else {
                                        s.parse::<u64>().ok()
                                    }
                                } else if let Some(n) = num_param.as_u64() {
                                    Some(n)
                                } else {
                                    None
                                };
                                (h, None)
                            },
                            _ => {
                                if let Some(s) = num_param.as_str() {
                                    if s.starts_with("0x") {
                                        let bytes = hex::decode(&s[2..]).ok();
                                        (None, bytes)
                                    } else {
                                        (None, None)
                                    }
                                } else {
                                    (None, None)
                                }
                            }
                        };
                        let lock = engine.lock().unwrap();
                        let target_block = if let Some(h) = height_opt {
                            lock.chain.get(h as usize)
                        } else if let Some(hh) = hash_opt {
                            lock.chain.iter().find(|b| compute_block_hash(b) == hh)
                        } else {
                            lock.chain.last()
                        };
                        if let Some(block) = target_block {
                            let block_hash = compute_block_hash(block);
                            let tx_hashes: Vec<String> = block.txs.iter().filter_map(|raw| {
                                serde_json::from_slice::<QuantumTransaction>(raw).ok().map(|qtx| {
                                    let mut h = Sha3_256::new();
                                    h.update(qtx.sender_pk.as_bytes());
                                    h.update(qtx.recipient.as_bytes());
                                    h.update(qtx.amount.as_bytes());
                                    h.update(qtx.nonce.to_be_bytes());
                                    h.update(qtx.signature.as_bytes());
                                    format!("0x{}", hex::encode(h.finalize()))
                                })
                            }).collect();
                            response.result = Some(serde_json::json!({
                                "number": format!("0x{:x}", block.height),
                                "hash": format!("0x{}", hex::encode(block_hash)),
                                "parentHash": format!("0x{}", hex::encode(&block.prev_hash)),
                                "transactions": tx_hashes,
                            }));
                        } else {
                            response.result = Some(serde_json::Value::Null);
                        }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                "faucet" => {
                    if let Network::Development = network {
                        if let Some(params) = req.params.as_slice().get(0..2) {
                            let addr_str = params[0].as_str().unwrap_or("0x0");
                            let amount_str = params[1].as_str().unwrap_or("0");
                            let amount: u128 = amount_str.parse().unwrap_or(0);
                            
                            let mut vm_lock = vm.lock().unwrap();
                            if let Ok(_) = vm_lock.mint(addr_str.to_string(), amount) {
                                let _ = vm_lock.save_to_disk("po8_evm_db.json");
                                response.result = Some(serde_json::json!(format!("Minted {} to {}", amount, addr_str)));
                            } else {
                                response.error = make_err(-32000, "Mint failed".to_string());
                            }
                        } else {
                             response.error = make_err(-32602, "Invalid params".to_string());
                        }
                    } else {
                        response.error = make_err(-32000, "Method disabled".to_string());
                    }
                },
                "send_transaction" => {
                    if let Some(tx_json) = req.params.get(0) {
                         if let Ok(qtx) = serde_json::from_value::<QuantumTransaction>(tx_json.clone()) {
                             println!("Received Quantum TX from PK: {}...", &qtx.sender_pk[0..10]);
                             
                             // Calculate TxHash
                             let mut hasher = Sha3_256::new();
                             hasher.update(qtx.sender_pk.as_bytes());
                             hasher.update(qtx.recipient.as_bytes());
                             hasher.update(qtx.amount.as_bytes());
                             hasher.update(qtx.nonce.to_be_bytes());
                             hasher.update(qtx.signature.as_bytes());
                             let tx_hash = format!("0x{}", hex::encode(hasher.finalize()));

                             // 1. Verify ML-DSA Signature
                             let pk_bytes = hex::decode(&qtx.sender_pk).unwrap_or_default();
                             let sig_bytes = hex::decode(&qtx.signature).unwrap_or_default();
                             
                             let data_str = qtx.data.clone().unwrap_or_default();
                             let msg = format!("{}:{}:{}:{}", qtx.recipient, qtx.amount, qtx.nonce, data_str);
                             let msg_bytes = msg.as_bytes();

                             if let Ok(valid) = MlDsa65::verify(msg_bytes, &sig_bytes, &pk_bytes) {
                                 if valid {
                                     let mut hasher = Sha3_256::new();
                                     hasher.update(&pk_bytes);
                                     let hash = hasher.finalize();
                                     let sender_addr = hex::encode(&hash[0..20]);
                                     let sender_addr_fmt = format!("0x{}", sender_addr);

                                    {
                                        let m_lock = mempool.lock().unwrap();
                                        let next = *m_lock.next_nonce.get(&sender_addr_fmt).unwrap_or(&0);
                                        if qtx.nonce < next {
                                            response.error = make_err(-32000, "Nonce too low".to_string());
                                            return warp::reply::json(&response);
                                        }
                                        if qtx.nonce > next + 1000 {
                                            response.error = make_err(-32000, "Nonce too high".to_string());
                                            return warp::reply::json(&response);
                                        }
                                        if m_lock.pending_txs.iter().any(|t| t.signature == qtx.signature) {
                                            response.result = Some(serde_json::json!("duplicate"));
                                            return warp::reply::json(&response);
                                        }
                                        if m_lock.pending_txs.len() > 2000 {
                                            response.error = make_err(-32000, "Mempool full".to_string());
                                            return warp::reply::json(&response);
                                        }
                                        
                                        // Fee/Balance Check
                                        let parsed_amount = qtx.amount.parse::<u128>().unwrap_or(0);
                                        let vm_lock = vm.lock().unwrap();
                                        let balance = vm_lock.get_balance(sender_addr_fmt.clone()).unwrap_or(0);
                                        if balance < parsed_amount + MIN_FEE_WEI {
                                            response.error = make_err(-32000, "Insufficient funds for value + fee".to_string());
                                            return warp::reply::json(&response);
                                        }
                                    }

                                     let amount: u128 = qtx.amount.parse().unwrap_or(0);
                                     let mut vm_lock = vm.lock().unwrap();
                                     
                                     let data_bytes = hex::decode(&data_str).unwrap_or_default();
                                     
                                     let execution_result = vm_lock.execute_transaction(sender_addr_fmt.clone(), qtx.recipient.clone(), amount, data_bytes);
                                     
                                     let (status, output, _contract_address) = match execution_result {
                                         Ok(res) => {
                                             if res.starts_with("Contract Created") {
                                                  ("0x1", res, None::<String>) 
                                             } else {
                                                 ("0x1", res, None::<String>)
                                             }
                                         },
                                         Err(e) => ("0x0", e, None::<String>),
                                     };
                                     
                                     if status == "0x1" {
                                         if let Err(e) = vm_lock.save_to_disk("po8_evm_db.json") {
                                             eprintln!("Failed to save EVM DB: {}", e);
                                         }
                                     }
                                     
                                     let receipt = serde_json::json!({
                                         "transactionHash": tx_hash,
                                         "transactionIndex": "0x0",
                                         "blockHash": "0x0", 
                                         "blockNumber": "0x0",
                                         "from": sender_addr_fmt,
                                         "to": if qtx.recipient == "0x" { None } else { Some(qtx.recipient.clone()) },
                                         "cumulativeGasUsed": "0x0",
                                         "gasUsed": "0x0",
                                         "contractAddress": null,
                                         "logs": [],
                                         "logsBloom": "0x0",
                                         "status": status,
                                         "output": output
                                     });
                                     
                                     let mut r_lock = receipts.lock().unwrap();
                                     r_lock.receipts.insert(tx_hash.clone(), receipt);
                                    r_lock.save_to_disk("po8_receipts.json");
                                     
                                     let mut m_lock = mempool.lock().unwrap();
                                     m_lock.pending_txs.push(qtx.clone());
                                    let entry = m_lock.next_nonce.entry(sender_addr_fmt.clone()).or_insert(qtx.nonce);
                                    if qtx.nonce >= *entry {
                                        *entry = qtx.nonce + 1;
                                    }
                                    m_lock.save_to_disk("po8_mempool.json");
                                     
                                     response.result = Some(serde_json::json!(tx_hash));
                                 } else {
                                     response.error = make_err(-32000, "Invalid ML-DSA Signature".to_string());
                                 }
                             } else {
                                 response.error = make_err(-32000, "Signature Verification Error".to_string());
                             }
                         } else if let Some(tx_data) = tx_json.as_str() {
                             response.error = make_err(-32602, "Legacy format deprecated. Use QuantumTransaction JSON.".to_string());
                         } else {
                             response.error = make_err(-32602, "Invalid params".to_string());
                         }
                    } else {
                        response.error = make_err(-32602, "Invalid params".to_string());
                    }
                },
                _ => {
                    response.error = make_err(-32601, "Method not found".to_string());
                }
            }

            warp::reply::json(&response)
        });

    // Spawn Mining Loop
    let miner_engine = engine.clone();
    let miner_store = mining_store.clone();
    let miner_mempool = mempool.clone();
    let miner_receipts = receipt_store.clone();
    let miner_key = keypair.secret_key.clone();
    
    tokio::spawn(async move {
        loop {
            // Check if mining is active
            let is_mining = {
                let lock = miner_store.lock().unwrap();
                lock.is_mining
            };

            if !is_mining {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                continue;
            }

            // Get context for mining
            let (prev_hash, height, next_difficulty, complexity) = {
                let lock = miner_engine.lock().unwrap();
                let last = lock.chain.last().unwrap();
                let prev_hash = compute_block_hash(last);
                let next_diff = lock.compute_next_difficulty();
                let complexity = std::env::var("PO8_COMPLEXITY").ok().and_then(|v| v.parse().ok()).unwrap_or(1024usize);
                (prev_hash, last.height, next_diff, complexity)
            };

            // Run Mining (Blocking)
            let start_time = std::time::Instant::now();
            let (nonce, proof, proof_vector, iterations) = tokio::task::spawn_blocking(move || {
                po8_miner::mine_block_mlx(&prev_hash, complexity, next_difficulty as usize)
            }).await.unwrap();
            let duration = start_time.elapsed();

            println!("Mined Block {}! Nonce: {}, Proof: {:02x?}...", height + 1, nonce, &proof[0..4]);
            
            // Construct and Sign Block
            // Collect Txs from Mempool
            let mut txs = vec![];
            {
                let mut m_lock = miner_mempool.lock().unwrap();
                // Drain all pending txs
                for qtx in m_lock.pending_txs.drain(..) {
                    if let Ok(bytes) = serde_json::to_vec(&qtx) {
                        txs.push(bytes);
                    }
                }
                m_lock.save_to_disk("po8_mempool.json");
            }

            {
                let mut lock = miner_engine.lock().unwrap();
                if lock.chain.len() as u64 == height + 1 {
                    let prev_block = lock.chain.last().unwrap();
                    let parent_hash = compute_block_hash(prev_block);
                    let tx_root = compute_txs_merkle(&txs);

                    let mut new_block = po8_consensus::Block {
                        height: prev_block.height + 1,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                        prev_hash: parent_hash, 
                        txs: txs.clone(),
                        tx_root,
                        nonce,
                        difficulty: next_difficulty,
                        proof: proof.to_vec(),
                        proof_vector: proof_vector,
                        signature: vec![],
                        proposer_address: format!("0x{}", address), // Self as proposer
                        last_commit: None, // Simplified for single-node mining (should be QC from previous block)
                    };

                    let block_bytes = new_block.compute_sign_bytes();
                    if let Ok(sig) = po8_crypto::MlDsa65::sign(&block_bytes, &miner_key) {
                        new_block.signature = sig;
                        if lock.add_block(new_block) {
                            let block_hash = compute_block_hash(lock.chain.last().unwrap());
                            // Update receipts with block info
                            {
                                let mut r_lock = miner_receipts.lock().unwrap();
                                for raw_tx in &txs {
                                    if let Ok(qtx) = serde_json::from_slice::<QuantumTransaction>(raw_tx) {
                                        let mut hasher = Sha3_256::new();
                                        hasher.update(qtx.sender_pk.as_bytes());
                                        hasher.update(qtx.recipient.as_bytes());
                                        hasher.update(qtx.amount.as_bytes());
                                        hasher.update(qtx.nonce.to_be_bytes());
                                        hasher.update(qtx.signature.as_bytes());
                                        let tx_hash = format!("0x{}", hex::encode(hasher.finalize()));
                                        r_lock.receipts.insert(tx_hash.clone(), serde_json::json!({
                                            "transactionHash": tx_hash,
                                            "blockHash": format!("0x{}", hex::encode(&block_hash)),
                                            "blockNumber": format!("0x{:x}", lock.chain.last().unwrap().height),
                                            "status": "0x1"
                                        }));
                                    }
                                }
                                r_lock.save_to_disk("po8_receipts.json");
                            }
                            let _ = lock.save_to_disk("po8_chain.json");
                            println!("Chain updated. Height: {}, Txs: {}", lock.chain.len(), txs.len());
                        }
                    }
                }
            }

            {
                let mut m_lock = miner_store.lock().unwrap();
                m_lock.blocks_mined += 1;
                m_lock.total_earnings += 10; 
                let secs = duration.as_secs_f64();
                if secs > 0.0 {
                    m_lock.hash_rate = (iterations as f64 / secs) as u64;
                } else {
                    // Sub-millisecond mining (very fast)
                    m_lock.hash_rate = iterations * 1000; 
                }
            }
        }
    });

    // Inbound P2P processing loop
    {
        let messages = message_store.clone();
        let peers = peers.clone();
        let p2p = p2p_server.clone();
        tokio::spawn(async move {
            while let Some(packet) = p2p_rx.recv().await {
                // Try Sphinx packet first
                if let Some(sphinx) = SphinxPacket::from_bytes(&packet) {
                    handle_sphinx(sphinx, &messages, &peers, &p2p);
                }
                // Try legacy JSON OnionFrame
                else if let Some(onion) = parse_onion(&packet) {
                    handle_onion(onion, &messages, &peers, &p2p);
                }
                // Try direct relay
                else if let Some(relay) = parse_relay(&packet) {
                    process_relay(relay, &messages, &peers, &p2p);
                }
            }
        });
    }

    println!("JSON-RPC listening on http://127.0.0.1:{}/rpc", rpc_port);
    println!("Node Dashboard available at http://127.0.0.1:{}/", rpc_port);
    
    let routes = rpc_route.or(dashboard_route).with(cors);
    warp::serve(routes).run(([127, 0, 0, 1], rpc_port)).await;
}
