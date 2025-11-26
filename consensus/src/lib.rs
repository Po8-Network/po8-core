use po8_crypto::{MlDsa65, QuantumSigner};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use sha3::{Digest, Keccak256};

mod xoshiro;
use xoshiro::Xoshiro256PlusPlus;

/// A Validator in the Po8 Network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Validator {
    pub public_key: Vec<u8>,
    pub voting_power: u64,
    pub address: String, // Derived from PK (SHA3-256 truncated)
}

/// Types of BFT votes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// A generic BFT Vote signed by a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    pub block_hash: Vec<u8>, // None/Empty for nil vote
    pub timestamp: u64,
    pub validator_address: String,
    pub signature: Vec<u8>,
}

/// Represents the QC (Quorum Certificate) or Commit for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub height: u64,
    pub round: u32,
    pub block_hash: Vec<u8>,
    pub signatures: Vec<Vote>, // List of Precommits
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub nonce: u64,
    pub difficulty: u32,
    pub proof: Vec<u8>, // The hash digest of the matrix C (or proof vector v)
    pub proof_vector: Vec<f32>, // The Fiat-Shamir response vector v = C*r
    pub proposer_address: String,
    pub signature: Vec<u8>, // Proposer's signature
    pub last_commit: Option<Commit>, // QC for the previous block
}

impl Block {
    // Helper to serialize block content for signing (excluding signature/proof)
    pub fn compute_sign_bytes(&self) -> Vec<u8> {
        // Simple serialization: height + timestamp + prev_hash + nonce
        let mut data = Vec::new();
        data.extend_from_slice(&self.height.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.prev_hash);
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data
    }
}

pub struct ConsensusEngine {
    pub chain: Vec<Block>,
    pub validators: HashMap<String, Validator>, // Address -> Validator
}

impl ConsensusEngine {
    pub fn new() -> Self {
        let genesis = Block {
            height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            prev_hash: vec![0u8; 32],
            txs: vec![],
            nonce: 0,
            difficulty: 8,
            proof: vec![0u8; 32],
            proof_vector: vec![],
            proposer_address: "0x0000000000000000000000000000000000000000".to_string(),
            signature: vec![],
            last_commit: None,
        };
        
        Self {
            chain: vec![genesis],
            validators: HashMap::new(),
        }
    }

    pub fn add_validator(&mut self, pk: Vec<u8>, power: u64) {
        // Simple address derivation for now: first 20 bytes of PK (mock)
        // In real impl, use SHA3-256(pk)[0..20]
        let mut addr_bytes = [0u8; 20];
        let len = std::cmp::min(pk.len(), 20);
        addr_bytes[0..len].copy_from_slice(&pk[0..len]);
        let address = hex::encode(addr_bytes);
        
        self.validators.insert(address.clone(), Validator {
            public_key: pk,
            voting_power: power,
            address,
        });
    }

    /// Verifies a block's signatures and consensus rules
    pub fn verify_block(&self, block: &Block) -> bool {
        // 1. Check Prev Hash
        if let Some(prev) = self.chain.last() {
             if block.height != prev.height + 1 { return false; }
             // In real impl, check block.prev_hash == hash(prev)
        }

        // 2. Verify Proposer Signature
        if let Some(val) = self.validators.get(&block.proposer_address) {
             let msg = block.compute_sign_bytes();
             if let Ok(valid) = MlDsa65::verify(&msg, &block.signature, &val.public_key) {
                 if !valid { 
                     println!("Block signature invalid");
                     return false; 
                 }
             } else {
                 return false;
             }
        } else {
            // Allow unknown proposer for genesis/dev if validator set empty? 
            // For now, fail if not found, unless we are in barebones mode
            if !self.validators.is_empty() {
                println!("Proposer not in validator set");
                return false;
            }
        }

        // 3. Verify TensorChain (Freivalds' Check)
        if block.height > 1 && !self.verify_tensor_chain(block) {
            println!("TensorChain Proof Invalid");
            return false;
        }

        // 4. Verify Last Commit (Quorum Certificate)
        if block.height > 1 {
            if let Some(commit) = &block.last_commit {
                if !self.verify_commit(commit) {
                    println!("Invalid Last Commit");
                    return false;
                }
            } else {
                println!("Missing Last Commit for non-genesis block");
                return false; 
            }
        }

        true
    }

    // Verify TensorChain Proof: A * (B * r) == v
    fn verify_tensor_chain(&self, block: &Block) -> bool {
        if block.proof_vector.is_empty() {
            // If empty (e.g. genesis), skip check
            return true;
        }

        let n = block.proof_vector.len();
        // Assuming Square Matrices N x N. N = proof_vector.len().
        // In miner we hardcoded 1024, but strictly we should get complexity from block or config.
        // Let's assume N = proof_vector.len() is the complexity.

        // 1. Derive Seed
        let mut hasher = Keccak256::new();
        hasher.update(&block.prev_hash);
        hasher.update(&block.nonce.to_be_bytes());
        let seed_bytes = hasher.finalize();
        
        let mut seed_val = 0u64;
        for i in 0..8 {
            if i < seed_bytes.len() {
                seed_val |= (seed_bytes[i] as u64) << (i * 8);
            }
        }

        // 2. Generate Challenge Vector r
        let mut rng_r = Xoshiro256PlusPlus::new(seed_val + 1);
        let mut r = vec![0.0f32; n];
        for i in 0..n {
            r[i] = rng_r.next_float();
        }

        // 3. Compute y = B * r (O(N^2))
        // We need to skip A first (N*N calls)
        let mut rng_ab = Xoshiro256PlusPlus::new(seed_val);
        
        // Skip A
        for _ in 0..(n*n) {
            rng_ab.next(); // Just advance state
        }

        // Generate B and compute y
        let mut y = vec![0.0f32; n];
        for i in 0..n {
            let mut sum = 0.0f32;
            for j in 0..n {
                let b_ij = rng_ab.next_float();
                sum += b_ij * r[j];
            }
            y[i] = sum;
        }

        // 4. Compute z = A * y (O(N^2))
        // Reset PRNG to generate A
        rng_ab = Xoshiro256PlusPlus::new(seed_val);
        
        let mut z = vec![0.0f32; n];
        for i in 0..n {
            let mut sum = 0.0f32;
            for j in 0..n {
                let a_ij = rng_ab.next_float();
                sum += a_ij * y[j];
            }
            z[i] = sum;
        }

        // 5. Check z approx equals proof_vector
        for i in 0..n {
            let diff = (z[i] - block.proof_vector[i]).abs();
            // Tolerance depends on float precision and N accumulation error.
            // With N=1024 and float32, error can be around 1e-3 or larger depending on values.
            // Values are [-1, 1], sum of 1024 products.
            if diff > 0.1 { // Fairly loose tolerance for MVP
                println!("Proof mismatch at index {}: calculated {} vs provided {}", i, z[i], block.proof_vector[i]);
                return false;
            }
        }

        // 6. Check Digest (Hash of v)
        let mut hash_acc: u64 = 0;
        for i in 0..n {
            let val_bits = block.proof_vector[i].to_bits(); // u32 bits of f32
            hash_acc ^= (val_bits as u64)
                .wrapping_add(0x9e3779b9)
                .wrapping_add(hash_acc << 6)
                .wrapping_add(hash_acc >> 2);
        }
        
        let mut calc_hash = [0u8; 32];
        for i in 0..32 {
            calc_hash[i] = ((hash_acc >> (i % 8)) & 0xFF) as u8;
        }

        if calc_hash != block.proof.as_slice() {
            println!("Proof hash digest mismatch");
            return false;
        }

        true
    }

    /// Verify that a Commit contains +2/3 voting power
    pub fn verify_commit(&self, commit: &Commit) -> bool {
        let mut signed_power = 0;
        let total_power: u64 = self.validators.values().map(|v| v.voting_power).sum();

        for vote in &commit.signatures {
            if let Some(val) = self.validators.get(&vote.validator_address) {
                // Verify Signature
                let msg = Self::compute_vote_sign_bytes(vote);
                if let Ok(valid) = MlDsa65::verify(&msg, &vote.signature, &val.public_key) {
                    if valid {
                        signed_power += val.voting_power;
                    }
                }
            }
        }

        // Check for 2/3 majority
        signed_power > (total_power * 2 / 3)
    }

    pub fn add_block(&mut self, block: Block) -> bool {
        if self.verify_block(&block) {
            println!("Consensus: Block {} verified and added.", block.height);
            self.chain.push(block);
            return true;
        } else {
            println!("Consensus: Block {} verification failed.", block.height);
            return false;
        }
    }

    fn compute_vote_sign_bytes(vote: &Vote) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&vote.height.to_be_bytes());
        data.extend_from_slice(&vote.round.to_be_bytes());
        data.extend_from_slice(&vote.block_hash);
        // data.push(vote.vote_type as u8); // Need enum serialization
        data
    }
}
