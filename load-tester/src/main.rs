use clap::Parser;
use po8_crypto::{MlDsa65, QuantumSigner};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of transactions to send
    #[arg(short, long, default_value_t = 10)]
    count: usize,

    /// RPC URL
    #[arg(short, long, default_value = "http://127.0.0.1:8833/rpc")]
    url: String,
}

#[derive(Serialize, Debug)]
struct QuantumTransaction {
    sender_pk: String,
    recipient: String,
    amount: String,
    nonce: u64,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let client = Client::new();

    println!("Starting load test with {} transactions to {}", args.count, args.url);

    let mut success_count = 0;
    let mut fail_count = 0;
    let start_time = Instant::now();

    for i in 0..args.count {
        // 1. Generate Sender Identity
        let keypair = MlDsa65::generate_keypair().expect("Failed to generate keypair");
        let pk_hex = hex::encode(&keypair.public_key);

        // 2. Prepare Transaction Data
        let recipient = "0x000000000000000000000000000000000000dead"; // Burn address
        let amount = "100"; // Wei
        let nonce = i as u64; // Simple nonce strategy for unique txs
        let data = "";

        // 3. Sign
        let msg = format!("{}:{}:{}:{}", recipient, amount, nonce, data);
        let signature = MlDsa65::sign(msg.as_bytes(), &keypair.secret_key).expect("Failed to sign");
        let sig_hex = hex::encode(signature);

        let tx = QuantumTransaction {
            sender_pk: pk_hex,
            recipient: recipient.to_string(),
            amount: amount.to_string(),
            nonce,
            signature: sig_hex,
            data: if data.is_empty() { None } else { Some(hex::encode(data)) },
        };

        // 4. Send RPC
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "send_transaction".to_string(),
            params: vec![serde_json::to_value(&tx).unwrap()],
            id: 1,
        };

        match client.post(&args.url).json(&req).send().await {
            Ok(resp) => {
                if let Ok(rpc_resp) = resp.json::<RpcResponse>().await {
                    if rpc_resp.error.is_none() {
                        success_count += 1;
                        if i % 10 == 0 {
                            print!(".");
                        }
                    } else {
                        fail_count += 1;
                        eprintln!("\nTx {} failed: {:?}", i, rpc_resp.error);
                    }
                } else {
                    fail_count += 1;
                    eprintln!("\nTx {} failed to parse response", i);
                }
            }
            Err(e) => {
                fail_count += 1;
                eprintln!("\nTx {} connection error: {}", i, e);
            }
        }
    }

    let duration = start_time.elapsed();
    println!("\n\nLoad test completed in {:.2?}", duration);
    println!("Total: {}", args.count);
    println!("Success: {}", success_count);
    println!("Failed: {}", fail_count);
    println!("TPS: {:.2}", success_count as f64 / duration.as_secs_f64());
}

