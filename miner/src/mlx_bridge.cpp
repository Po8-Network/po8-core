#include "mlx_bridge.hpp"
#include "xoshiro.hpp"
#include <vector>
#include <random>
#include <iostream>
#include <cstring>

// Check if MLX is available
#if __has_include(<mlx/mlx.h>)
    #include <mlx/mlx.h>
    #define HAS_MLX 1
#else
    #define HAS_MLX 0
#endif

void compute_tensor_chain_proof(
    const uint8_t* seed, 
    size_t seed_len, 
    size_t complexity, 
    uint8_t* result_hash,
    float* proof_vector
) {
    unsigned long seed_val = 0;
    for(size_t i=0; i<8 && i<seed_len; i++) seed_val |= (unsigned long)seed[i] << (i*8);
    
    int N = (int)complexity;
    
    // 1. Host generation using portable PRNG
    // We allocate buffers on CPU
    std::vector<float> a_host(N * N);
    std::vector<float> b_host(N * N);
    std::vector<float> r_host(N);

    // Initialize PRNG for A and B
    Xoshiro256PlusPlus rng(seed_val);
    
    // Fill A
    for(int i=0; i<N*N; i++) {
        a_host[i] = rng.next_float();
    }
    // Fill B
    for(int i=0; i<N*N; i++) {
        b_host[i] = rng.next_float();
    }

    // Initialize PRNG for r (salt = seed + 1)
    Xoshiro256PlusPlus rng_r(seed_val + 1);
    for(int i=0; i<N; i++) {
        r_host[i] = rng_r.next_float();
    }

    #if HAS_MLX
        try {
            // 2. Transfer to MLX Arrays
            // shape {N, N} for A, B. shape {N, 1} for r.
            auto A = mlx::core::array(a_host.data(), {N, N}, mlx::core::float32);
            auto B = mlx::core::array(b_host.data(), {N, N}, mlx::core::float32);
            auto r = mlx::core::array(r_host.data(), {N, 1}, mlx::core::float32);
            
            // 3. Compute C = A * B (O(N^3))
            // We use 'matmul' which dispatches to Metal on macOS
            auto C = mlx::core::matmul(A, B);
            
            // 4. Compute v = C * r (O(N^2))
            auto v = mlx::core::matmul(C, r);
            mlx::core::eval(v); // Force computation

            // 5. Output Proof Vector
            const float* v_data = v.data<float>();
            std::memcpy(proof_vector, v_data, N * sizeof(float));

            // 6. Compute Digest (Hash of v)
            // Just hash the output vector for the block header
            uint64_t hash_acc = 0;
            for(int i=0; i<N; i++) {
                // Simple mixing hash
                uint32_t val_bits;
                std::memcpy(&val_bits, &v_data[i], 4);
                hash_acc ^= (uint64_t)val_bits + 0x9e3779b9 + (hash_acc << 6) + (hash_acc >> 2);
            }
            
            for(int i=0; i<32; i++) {
                result_hash[i] = (hash_acc >> (i % 8)) & 0xFF;
            }

        } catch (const std::exception& e) {
            std::cerr << "MLX Error: " << e.what() << std::endl;
            std::memset(result_hash, 0xEE, 32);
        }
    #else
        // CPU Mock using simple loops (for validation on non-macOS dev)
        // Note: For large N this will be slow, but dev usage usually has small N.
        
        // C = A * B (Slow!)
        // v = C * r
        // Equivalent to v = A * (B * r) which is faster O(N^2).
        // Since we are simulating the "work", we can just do the fast way for the mock result
        // BUT the miner is supposed to do the hard work (compute C).
        // For the mock, we cheat and do the O(N^2) verification path to generate the proof, 
        // effectively being a "lazy miner" but producing valid proofs.
        
        // 1. y = B * r
        std::vector<float> y(N, 0.0f);
        for(int i=0; i<N; i++) { // Row i of B
            float sum = 0.0f;
            for(int j=0; j<N; j++) {
                sum += b_host[i*N + j] * r_host[j];
            }
            y[i] = sum;
        }

        // 2. v = A * y
        std::vector<float> v(N, 0.0f);
        for(int i=0; i<N; i++) { // Row i of A
            float sum = 0.0f;
            for(int j=0; j<N; j++) {
                sum += a_host[i*N + j] * y[j];
            }
            v[i] = sum;
        }
        
        std::memcpy(proof_vector, v.data(), N * sizeof(float));
        
        uint64_t hash_acc = 0;
        for(int i=0; i<N; i++) {
            uint32_t val_bits;
            std::memcpy(&val_bits, &v[i], 4);
            hash_acc ^= (uint64_t)val_bits + 0x9e3779b9 + (hash_acc << 6) + (hash_acc >> 2);
        }
        for(int i=0; i<32; i++) {
            result_hash[i] = (hash_acc >> (i % 8)) & 0xFF;
        }
    #endif
}
