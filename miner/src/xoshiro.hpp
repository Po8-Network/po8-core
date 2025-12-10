#pragma once
#include <cstdint>
#include <limits>

// Xoshiro256++ implementation
// Seeded with a 64-bit seed (split into 4 uint64_t state parts)
struct Xoshiro256PlusPlus {
    uint64_t s[4];

    static inline uint64_t rotl(const uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }

    static inline uint64_t splitmix64(uint64_t& x) {
        uint64_t z = (x += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    Xoshiro256PlusPlus(uint64_t seed) {
        // Initialize state using SplitMix64
        s[0] = splitmix64(seed);
        s[1] = splitmix64(seed);
        s[2] = splitmix64(seed);
        s[3] = splitmix64(seed);
    }

    uint64_t next() {
        const uint64_t result = rotl(s[0] + s[3], 23) + s[0];

        const uint64_t t = s[1] << 17;

        s[2] ^= s[0];
        s[1] ^= s[1];
        s[0] ^= s[2];
        s[3] ^= s[1];

        s[1] ^= t;
        s[3] = rotl(s[3], 45);

        return result;
    }

    // Generate float in range [-1.0, 1.0]
    float next_float() {
        // Generate random 24 bits for mantissa
        uint32_t r = (uint32_t)(next() >> 40); 
        // Normalize to [0, 1]
        float f = (float)r / (float)(1 << 24);
        // Map to [-1, 1]
        return f * 2.0f - 1.0f;
    }
};






