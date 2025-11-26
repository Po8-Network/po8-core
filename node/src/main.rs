use po8_crypto::{MlDsa65, QuantumSigner};
use po8_consensus::ConsensusEngine;
use po8_vm::EvmEngine;
use std::sync::{Arc, Mutex};
use warp::Filter;
use std::env;
use sha3::{Digest, Sha3_256};

mod p2p; // Import P2P module

#[derive(serde::Deserialize)]
struct RpcRequest {
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(serde::Serialize)]
struct RpcResponse {
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<String>,
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

// Define Quantum Transaction structure for deserialization
#[derive(serde::Deserialize)]
struct QuantumTransaction {
    sender_pk: String, // Hex encoded ML-DSA-65 Public Key
    recipient: String, // Hex encoded 20-byte address
    amount: String,    // String number
    nonce: u64,
    signature: String, // Hex encoded ML-DSA-65 Signature
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

    // Derive Address: SHA3-256(PublicKey)[0..20] -> Hex
    let mut hasher = Sha3_256::new();
    hasher.update(&keypair.public_key);
    let result = hasher.finalize();
    let address = hex::encode(&result[0..20]); // Ethereum-style 20-byte address
    println!("Miner Address: 0x{}", address);

    // Initialize P2P Server
    tokio::spawn(async {
        if let Ok(p2p) = p2p::P2PServer::new(8834) {
            if let Err(e) = p2p.start().await {
                eprintln!("P2P Server Error: {}", e);
            }
        }
    });

    // Initialize Stores
    let mut consensus_engine = ConsensusEngine::new();
    // Register self as validator (Genesis validator)
    consensus_engine.add_validator(keypair.public_key.clone(), 100);
    
    let engine = Arc::new(Mutex::new(consensus_engine));
    
    // Initialize EVM
    let mut evm_engine = EvmEngine::new();
    // Mint initial funds to miner for testing
    if let Err(e) = evm_engine.mint(format!("0x{}", address), 1000_000_000_000_000_000_000) { // 1000 ETH/PO8
        eprintln!("Failed to mint genesis funds: {}", e);
    }
    let vm = Arc::new(Mutex::new(evm_engine));

    let mining_store = Arc::new(Mutex::new(MiningStore {
        blocks_mined: 0,
        total_earnings: 0,
        hash_rate: 0,
        miner_address: format!("0x{}", address),
        is_mining: true, // Auto-start mining
    }));

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

    // CORS
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["POST", "GET"]);

    // Dashboard Route (Serve Static Files)
    let dashboard_route = warp::get()
        .and(warp::fs::dir("../po8-core/node-dashboard/dist"));

    // JSON-RPC Route
    let rpc_route = warp::post()
        .and(warp::path("rpc"))
        .and(warp::body::json())
        .and(engine_filter)
        .and(vm_filter)
        .and(mining_filter)
        .map(move |req: RpcRequest, engine: Arc<Mutex<ConsensusEngine>>, vm: Arc<Mutex<EvmEngine>>, mining: Arc<Mutex<MiningStore>>| {
            let mut response = RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
                id: req.id,
            };

            match req.method.as_str() {
                "net_version" => {
                    response.result = Some(serde_json::json!(network.chain_id()));
                },
                "get_block_count" => {
                    let lock = engine.lock().unwrap();
                    response.result = Some(serde_json::json!(lock.chain.len()));
                },
                "get_balance" => {
                    // If address param provided, use it, else dummy default
                    let addr = if let Some(a) = req.params.get(0).and_then(|v| v.as_str()) {
                        a.to_string()
                    } else {
                        "0x0000000000000000000000000000000000000000".to_string()
                    };

                    let lock = vm.lock().unwrap();
                    match lock.get_balance(addr) {
                        Ok(bal) => response.result = Some(serde_json::json!(bal.to_string())),
                        Err(e) => response.error = Some(e),
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
                        "peer_count": 8, // Mocked for now, could hook into P2P module
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
                            response.result = Some(serde_json::json!(block));
                        } else {
                            response.error = Some("Block not found".to_string());
                        }
                    } else {
                        response.error = Some("Invalid params".to_string());
                    }
                },
                "get_fee_estimates" => {
                    response.result = Some(serde_json::json!({
                        "base_fee": "0.000000001",
                        "priority_fee": "0.000000001",
                        "estimated_cost": "0.001"
                    }));
                },
                "send_transaction" => {
                    // Expect JSON object for Quantum Transaction
                    if let Some(tx_json) = req.params.get(0) {
                         // Check for Quantum Transaction format
                         if let Ok(qtx) = serde_json::from_value::<QuantumTransaction>(tx_json.clone()) {
                             println!("Received Quantum TX from PK: {}...", &qtx.sender_pk[0..10]);
                             
                             // 1. Verify ML-DSA Signature
                             let pk_bytes = hex::decode(&qtx.sender_pk).unwrap_or_default();
                             let sig_bytes = hex::decode(&qtx.signature).unwrap_or_default();
                             
                             // Reconstruct message: recipient:amount:nonce (Simple serialization for MVP)
                             let msg = format!("{}:{}:{}", qtx.recipient, qtx.amount, qtx.nonce);
                             let msg_bytes = msg.as_bytes();

                             if let Ok(valid) = MlDsa65::verify(msg_bytes, &sig_bytes, &pk_bytes) {
                                 if valid {
                                     println!("Quantum Signature Verified! Executing in EVM...");
                                     
                                     // 2. Derive Sender Address (SHA3-256(pk)[0..20])
                                     let mut hasher = Sha3_256::new();
                                     hasher.update(&pk_bytes);
                                     let hash = hasher.finalize();
                                     let sender_addr = hex::encode(&hash[0..20]);
                                     let sender_addr_fmt = format!("0x{}", sender_addr);

                                     // 3. Execute in EVM (Quantum Abstraction Layer)
                                     let amount: u128 = qtx.amount.parse().unwrap_or(0);
                                     let mut vm_lock = vm.lock().unwrap();
                                     
                                     // Mint gas/funds if needed for Devnet
                                     let _ = vm_lock.mint(sender_addr_fmt.clone(), amount + 1000); 

                                     match vm_lock.execute_transaction(sender_addr_fmt, qtx.recipient.clone(), amount, vec![]) {
                                         Ok(res) => response.result = Some(serde_json::json!(res)),
                                         Err(e) => response.error = Some(e),
                                     }
                                 } else {
                                     response.error = Some("Invalid ML-DSA Signature".to_string());
                                 }
                             } else {
                                 response.error = Some("Signature Verification Error".to_string());
                             }
                         } else if let Some(tx_data) = tx_json.as_str() {
                             // Fallback for deprecated string format (e.g. "send:to:amt")
                             // We should remove this soon, but keeping for backward compat during dev transition
                             response.error = Some("Legacy format deprecated. Use QuantumTransaction JSON.".to_string());
                         } else {
                             response.error = Some("Invalid params".to_string());
                         }
                    } else {
                        response.error = Some("Invalid params".to_string());
                    }
                },
                _ => {
                    response.error = Some("Method not found".to_string());
                }
            }

            warp::reply::json(&response)
        });

    // Spawn Mining Loop
    let miner_engine = engine.clone();
    let miner_store = mining_store.clone();
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
            let (prev_hash, height) = {
                let lock = miner_engine.lock().unwrap();
                let last = lock.chain.last().unwrap();
                (last.prev_hash.clone(), last.height)
            };

            // Run Mining (Blocking)
            let start_time = std::time::Instant::now();
            let (nonce, proof, proof_vector, iterations) = tokio::task::spawn_blocking(move || {
                po8_miner::mine_block_mlx(&prev_hash, 1024, 8)
            }).await.unwrap();
            let duration = start_time.elapsed();

            println!("Mined Block {}! Nonce: {}, Proof: {:02x?}...", height + 1, nonce, &proof[0..4]);
            
            // Construct and Sign Block
            let txs = vec![];
            {
                let mut lock = miner_engine.lock().unwrap();
                if lock.chain.len() as u64 == height + 1 {
                    let prev_block = lock.chain.last().unwrap();
                    let mut new_block = po8_consensus::Block {
                        height: prev_block.height + 1,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                        prev_hash: prev_block.prev_hash.clone(), 
                        txs: txs.clone(),
                        nonce,
                        difficulty: 8,
                        proof: proof.to_vec(),
                        proof_vector: proof_vector,
                        signature: vec![],
                        proposer_address: format!("0x{}", address), // Self as proposer
                        last_commit: None, // Simplified for single-node mining (should be QC from previous block)
                    };

                    let block_bytes = new_block.compute_sign_bytes();
                    if let Ok(sig) = po8_crypto::MlDsa65::sign(&block_bytes, &miner_key) {
                        new_block.signature = sig;
                        lock.add_block(new_block);
                        println!("Chain updated. Height: {}", lock.chain.len());
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

    println!("JSON-RPC listening on http://127.0.0.1:8833/rpc");
    println!("Node Dashboard available at http://127.0.0.1:8833/");
    
    let routes = rpc_route.or(dashboard_route).with(cors);
    warp::serve(routes).run(([127, 0, 0, 1], 8833)).await;
}
