#pragma once

#include <cstdint>
#include <cstddef>

extern "C" {
    // Generate A, B from seed. Compute C = A*B.
    // Generate r from seed+salt.
    // Compute v = C*r.
    // Stores v in proof_vector (must be size 'complexity' floats).
    // Stores hash of v (or C) in result_hash (32 bytes).
    void compute_tensor_chain_proof(
        const uint8_t* seed, 
        size_t seed_len, 
        size_t complexity, 
        uint8_t* result_hash,
        float* proof_vector
    );
}

