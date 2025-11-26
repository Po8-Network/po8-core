use libc::size_t;
use sha3::{Digest, Keccak256};

#[link(name = "mlx_bridge", kind = "static")]
extern "C" {
    fn compute_tensor_chain_proof(
        seed: *const u8,
        seed_len: size_t,
        complexity: size_t,
        result_hash: *mut u8,
        proof_vector: *mut f32, // New output: The vector v = C*r
    );
}

/// Mines a block by finding a nonce.
/// Returns (nonce, proof_hash, proof_vector, iterations)
pub fn mine_block_mlx(prev_hash: &[u8], complexity: usize, difficulty_zeros: usize) -> (u64, [u8; 32], Vec<f32>, u64) {
    let mut nonce: u64 = 0;
    let mut result_hash = [0u8; 32];
    let mut proof_vector = vec![0.0f32; complexity];
    
    loop {
        // 1. Derive Seed
        let mut hasher = Keccak256::new();
        hasher.update(prev_hash);
        hasher.update(&nonce.to_be_bytes());
        let seed = hasher.finalize();

        // 2. Compute Matrix Product & Proof
        #[cfg(target_os = "macos")]
        unsafe {
            compute_tensor_chain_proof(
                seed.as_ptr(),
                seed.len(),
                complexity as size_t,
                result_hash.as_mut_ptr(),
                proof_vector.as_mut_ptr(),
            );
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Mock work
            let mut mock_hasher = Keccak256::new();
            mock_hasher.update(&seed);
            let mock_res = mock_hasher.finalize();
            result_hash.copy_from_slice(&mock_res);
            // Mock vector
            for i in 0..complexity {
                proof_vector[i] = 1.0;
            }
        }

        // 3. Check Difficulty
        if check_difficulty(&result_hash, difficulty_zeros) {
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
