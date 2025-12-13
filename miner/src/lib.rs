use po8_consensus::compute_proof_vector_and_hash;

/// Mines a block by finding a nonce.
/// Returns (nonce, proof_hash, proof_vector, iterations)
pub fn mine_block_mlx(prev_hash: &[u8], complexity: usize, difficulty_zeros: usize) -> (u64, [u8; 32], Vec<f32>, u64) {
    let mut nonce: u64 = 0;
    let mut result_hash = [0u8; 32];
    let mut proof_vector = vec![0.0f32; complexity];
    
    loop {
        // 1-2. Compute deterministic TensorChain proof vector/hash (matches consensus verifier)
        let (vec_out, proof_hash) = compute_proof_vector_and_hash(prev_hash, nonce, complexity);
        proof_vector.copy_from_slice(&vec_out);
        result_hash.copy_from_slice(&proof_hash);

        // 3. Check Difficulty on proof hash
        if check_difficulty(&proof_hash, difficulty_zeros) {
            return (nonce, result_hash, proof_vector, nonce + 1);
        }

        nonce += 1;
        
        // Safety break for dev environment (prevent infinite loop if difficulty too high)
        // if nonce > 10000000 { break; }
    }
}

fn check_difficulty(hash: &[u8], zeros: usize) -> bool {
    let mut zero_bits = 0;
    for &byte in hash {
        if byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros() as usize;
            break;
        }
    }
    zero_bits >= zeros
}
