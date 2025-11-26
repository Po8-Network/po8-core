use po8_miner::mine_block_mlx;
use std::time::Instant;

fn main() {
    println!("Starting Po8 Apple Silicon Miner...");
    
    let seed = [0u8; 32]; // Genesis seed
    let complexity = 1024; // Matrix dimension N
    
    let difficulty = 8;
    
    println!("Mining with complexity N={}...", complexity);
    let start = Instant::now();
    
    let (nonce, proof_hash, proof_vector, iterations) = mine_block_mlx(&seed, complexity, difficulty);
    
    let duration = start.elapsed();
    println!("Block mined in {:?}! Nonce: {}, Proof: {:02x?}...", duration, nonce, &proof_hash[0..4]);
    println!("Proof Vector Size: {}", proof_vector.len());
}

