use po8_crypto::{MlDsa65, QuantumSigner};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use sha3::{Digest, Keccak256, Sha3_256};
use sha3::digest::Output;
use tempfile::NamedTempFile;

pub mod xoshiro;
pub use xoshiro::Xoshiro256PlusPlus;

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

#[derive(Serialize, Deserialize)]
struct PersistedConsensus {
    chain: Vec<Block>,
    validators: HashMap<String, Validator>,
    observed_votes: HashMap<(u64, u32, String), Vec<u8>>,
    slashed: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub tx_root: Vec<u8>,
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
        let mut data = Vec::new();
        data.extend_from_slice(&self.height.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.prev_hash);
        data.extend_from_slice(&self.tx_root);
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.difficulty.to_be_bytes());
        data.extend_from_slice(&self.proof);
        data
    }
}

/// Normalize an address to lower-hex with 0x prefix.
fn normalize_address(addr: &str) -> String {
    let trimmed = addr.trim_start_matches("0x");
    format!("0x{}", trimmed.to_lowercase())
}

/// Derive an address from a public key: keccak256(pk)[0..20], 0x-prefixed.
pub fn derive_address(pk: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(pk);
    let digest = hasher.finalize();
    format!("0x{}", hex::encode(&digest[..20]))
}

/// Compute the deterministic TensorChain proof vector and hash for a given seed (prev_hash, nonce).
pub fn compute_proof_vector_and_hash(prev_hash: &[u8], nonce: u64, n: usize) -> (Vec<f32>, [u8; 32]) {
    // Seed derivation matches verify_tensor
    let mut hasher = Keccak256::new();
    hasher.update(prev_hash);
    hasher.update(&nonce.to_be_bytes());
    let seed_bytes = hasher.finalize();

    let mut seed_val = 0u64;
    for i in 0..8 {
        if i < seed_bytes.len() {
            seed_val |= (seed_bytes[i] as u64) << (i * 8);
        }
    }

    // Challenge vector r
    let mut rng_r = Xoshiro256PlusPlus::new(seed_val + 1);
    let mut r = vec![0.0f32; n];
    for i in 0..n {
        r[i] = rng_r.next_float();
    }

    // Generate B and compute y = B * r
    let mut rng_ab = Xoshiro256PlusPlus::new(seed_val);
    // skip A
    for _ in 0..(n * n) {
        rng_ab.next();
    }
    let mut y = vec![0.0f32; n];
    for i in 0..n {
        let mut sum = 0.0f32;
        for j in 0..n {
            let b_ij = rng_ab.next_float();
            sum += b_ij * r[j];
        }
        y[i] = sum;
    }

    // Generate A and compute z = A * y
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

    let proof_hash = compute_proof_hash(&z);
    (z, proof_hash)
}

/// Compute the proof hash digest from a proof vector (matches verifier check).
pub fn compute_proof_hash(proof_vector: &[f32]) -> [u8; 32] {
    let mut hash_acc: u64 = 0;
    for v in proof_vector {
        let val_bits = v.to_bits(); // u32 bits of f32
        hash_acc ^= (val_bits as u64)
            .wrapping_add(0x9e3779b9)
            .wrapping_add(hash_acc << 6)
            .wrapping_add(hash_acc >> 2);
    }

    let mut calc_hash = [0u8; 32];
    for i in 0..32 {
        calc_hash[i] = ((hash_acc >> (i % 8)) & 0xFF) as u8;
    }
    calc_hash
}

/// Compute Merkle root of transactions (Keccak256). Empty -> zero hash.
pub fn compute_txs_merkle(txs: &[Vec<u8>]) -> Vec<u8> {
    if txs.is_empty() {
        return vec![0u8; 32];
    }

    let mut layer: Vec<Vec<u8>> = txs.iter().map(|tx| {
        let mut h = Keccak256::new();
        h.update(tx);
        h.finalize().to_vec()
    }).collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks(2) {
            let mut h = Keccak256::new();
            h.update(&pair[0]);
            if pair.len() == 2 {
                h.update(&pair[1]);
            } else {
                h.update(&pair[0]); // duplicate last for odd count
            }
            next.push(h.finalize().to_vec());
        }
        layer = next;
    }

    layer[0].clone()
}

/// Compute the canonical hash of a block, including header, txs, proof, and commit
pub fn compute_block_hash(block: &Block) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(&block.height.to_be_bytes());
    hasher.update(&block.timestamp.to_be_bytes());
    hasher.update(&block.prev_hash);
    hasher.update(&block.tx_root);
    hasher.update(&block.nonce.to_be_bytes());
    hasher.update(&block.difficulty.to_be_bytes());
    hasher.update(&block.proof);
    for v in &block.proof_vector {
        hasher.update(&v.to_be_bytes());
    }
    // Transactions
    for tx in &block.txs {
        hasher.update(&(tx.len() as u64).to_be_bytes());
        hasher.update(tx);
    }
    hasher.update(block.proposer_address.as_bytes());
    hasher.update(&block.signature);

    // Last commit (if any)
    if let Some(commit) = &block.last_commit {
        hasher.update(&commit.height.to_be_bytes());
        hasher.update(&commit.round.to_be_bytes());
        hasher.update(&commit.block_hash);
        for vote in &commit.signatures {
            hasher.update(&vote.height.to_be_bytes());
            hasher.update(&vote.round.to_be_bytes());
            hasher.update(&vote.block_hash);
            hasher.update(&vote.timestamp.to_be_bytes());
            let vote_type_byte: u8 = match vote.vote_type {
                VoteType::Prevote => 0,
                VoteType::Precommit => 1,
            };
            hasher.update(&[vote_type_byte]);
            hasher.update(vote.validator_address.as_bytes());
            hasher.update(&vote.signature);
        }
    }

    let result: Output<Keccak256> = hasher.finalize();
    result.to_vec()
}

pub struct ConsensusEngine {
    pub chain: Vec<Block>,
    pub blocks_by_hash: HashMap<Vec<u8>, Block>,
    pub work_by_hash: HashMap<Vec<u8>, u128>,
    pub orphans: HashMap<Vec<u8>, Vec<Block>>,
    pub validators: HashMap<String, Validator>, // Address -> Validator
    pub observed_votes: HashMap<(u64, u32, String), Vec<u8>>, // (height, round, validator) -> block_hash
    pub slashed: HashSet<String>,
}

const TARGET_BLOCK_TIME: u64 = 30; // seconds
const RETARGET_WINDOW: usize = 10;
const MIN_DIFFICULTY: u32 = 4;
const MAX_DIFFICULTY: u32 = 32;

impl ConsensusEngine {
    pub fn new() -> Self {
        let genesis = Block {
            height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            prev_hash: vec![0u8; 32],
            txs: vec![],
            tx_root: compute_txs_merkle(&[]),
            nonce: 0,
            difficulty: 8,
            proof: vec![0u8; 32],
            proof_vector: vec![],
            proposer_address: "0x0000000000000000000000000000000000000000".to_string(),
            signature: vec![],
            last_commit: None,
        };
        
        Self {
            blocks_by_hash: HashMap::from([(compute_block_hash(&genesis), genesis.clone())]),
            work_by_hash: HashMap::from([(compute_block_hash(&genesis), genesis.difficulty as u128)]),
            orphans: HashMap::new(),
            chain: vec![genesis],
            validators: HashMap::new(),
            observed_votes: HashMap::new(),
            slashed: HashSet::new(),
        }
    }

    pub fn load_from_disk(path: &str) -> Result<Self, String> {
        if !std::path::Path::new(path).exists() {
            return Err("chain file not found".into());
        }
        let file = File::open(path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);
        let persisted: PersistedConsensus = serde_json::from_reader(reader).map_err(|e| e.to_string())?;
        let mut engine = Self {
            chain: persisted.chain,
            validators: persisted.validators,
            observed_votes: persisted.observed_votes,
            slashed: persisted.slashed,
            blocks_by_hash: HashMap::new(),
            work_by_hash: HashMap::new(),
            orphans: HashMap::new(),
        };
        if engine.validate_chain() {
            engine.rebuild_indexes();
            Ok(engine)
        } else {
            Err("chain validation failed".into())
        }
    }

    pub fn save_to_disk(&self, path: &str) -> Result<(), String> {
        let persisted = PersistedConsensus {
            chain: self.chain.clone(),
            validators: self.validators.clone(),
            observed_votes: self.observed_votes.clone(),
            slashed: self.slashed.clone(),
        };
        let tmp = NamedTempFile::new().map_err(|e| e.to_string())?;
        {
            let writer = BufWriter::new(&tmp);
            serde_json::to_writer_pretty(writer, &persisted).map_err(|e| e.to_string())?;
        }
        tmp.persist(path).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn rebuild_indexes(&mut self) {
        self.blocks_by_hash.clear();
        self.work_by_hash.clear();
        let mut cumulative: u128 = 0;
        for blk in &self.chain {
            let h = compute_block_hash(blk);
            cumulative = cumulative.saturating_add(blk.difficulty as u128);
            self.blocks_by_hash.insert(h.clone(), blk.clone());
            self.work_by_hash.insert(h, cumulative);
        }
        self.orphans.clear();
        // observed_votes already loaded
    }

    fn validate_chain(&self) -> bool {
        if self.chain.is_empty() {
            return false;
        }
        for w in self.chain.windows(2) {
            let prev = &w[0];
            let curr = &w[1];
            if curr.height != prev.height + 1 {
                println!("Chain validation failed: non-contiguous heights");
                return false;
            }
            if curr.prev_hash != compute_block_hash(prev) {
                println!("Chain validation failed: prev_hash mismatch");
                return false;
            }
            if compute_txs_merkle(&curr.txs) != curr.tx_root {
                println!("Chain validation failed: tx_root mismatch");
                return false;
            }
        }
        true
    }

    pub fn add_validator(&mut self, pk: Vec<u8>, power: u64) {
        let address = derive_address(&pk);
        self.validators.insert(address.clone(), Validator {
            public_key: pk,
            voting_power: power,
            address,
        });
    }

    pub fn remove_validator(&mut self, addr: &str) {
        let norm = normalize_address(addr);
        self.validators.remove(&norm);
    }

    pub fn slash_validator(&mut self, addr: &str, slash_power: u64) {
        let norm = normalize_address(addr);
        if let Some(v) = self.validators.get_mut(&norm) {
            v.voting_power = v.voting_power.saturating_sub(slash_power);
            if v.voting_power == 0 {
                self.validators.remove(&norm);
            }
        }
    }

    /// Verifies a block's signatures and consensus rules
    pub fn verify_block(&mut self, block: &Block) -> bool {
        // 1. Check Prev Hash via blocks map
        if block.height == 0 {
            // Genesis
        } else if let Some(prev) = self.blocks_by_hash.get(&block.prev_hash) {
            if block.height != prev.height + 1 { return false; }
            let expected_prev = compute_block_hash(prev);
            if block.prev_hash != expected_prev {
                println!("Prev hash mismatch");
                return false;
            }
        } else {
            println!("Missing parent for block {}", block.height);
            return false;
        }

        // 1a. Difficulty check (skip genesis)
        if block.height > 0 {
            let expected_diff = self.compute_next_difficulty();
            if block.difficulty != expected_diff {
                println!("Difficulty mismatch: got {}, expected {}", block.difficulty, expected_diff);
                return false;
            }
        }

        // 1b. Check tx root matches txs
        let expected_root = compute_txs_merkle(&block.txs);
        if block.tx_root != expected_root {
            println!("Tx root mismatch");
            return false;
        }

        // 2. Verify Proposer Signature
        let proposer_addr = normalize_address(&block.proposer_address);

        if self.slashed.contains(&proposer_addr) {
            println!("Proposer is slashed");
            return false;
        }

        if let Some(val) = self.validators.get(&proposer_addr) {
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
            if block.height > 0 {
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
                if commit.height + 1 != block.height {
                    println!("Commit height mismatch");
                    return false;
                }
                if commit.block_hash != block.prev_hash {
                    println!("Commit block hash mismatch");
                    return false;
                }
                if self.verify_commit(commit).is_none() {
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

    /// Compute next difficulty based on recent block times (simple retarget).
    pub fn compute_next_difficulty(&self) -> u32 {
        if self.chain.is_empty() {
            return MIN_DIFFICULTY;
        }
        let last = self.chain.last().unwrap();
        if self.chain.len() < 2 {
            return last.difficulty;
        }

        let window: Vec<&Block> = self.chain.iter().rev().take(RETARGET_WINDOW).collect();
        let first = window.last().unwrap();
        let last_ts = last.timestamp;
        let first_ts = first.timestamp;
        let span = last_ts.saturating_sub(first_ts);
        let intervals = (window.len() - 1).max(1) as u64;
        let avg = span / intervals;

        let mut difficulty = last.difficulty;
        if avg < TARGET_BLOCK_TIME / 2 {
            difficulty = difficulty.saturating_add(1);
        } else if avg > TARGET_BLOCK_TIME * 2 {
            difficulty = difficulty.saturating_sub(1);
        }
        difficulty = difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
        difficulty
    }

    // Verify TensorChain Proof: A * (B * r) == v
    fn verify_tensor_chain(&self, block: &Block) -> bool {
        if block.proof_vector.is_empty() {
            // If empty (e.g. genesis), skip check
            return true;
        }

        let n = block.proof_vector.len();
        let (expected_vec, expected_hash) = compute_proof_vector_and_hash(&block.prev_hash, block.nonce, n);

        // Check vector closeness
        for i in 0..n {
            let diff = (expected_vec[i] - block.proof_vector[i]).abs();
            if diff > 0.1 {
                println!("Proof mismatch at index {}: calculated {} vs provided {}", i, expected_vec[i], block.proof_vector[i]);
                return false;
            }
        }

        // Hash check
        if expected_hash != block.proof.as_slice() {
            println!("Proof hash digest mismatch");
            return false;
        }

        true
    }

    /// Verify that a Commit contains +2/3 voting power; returns signed power on success
    pub fn verify_commit(&mut self, commit: &Commit) -> Option<u64> {
        let mut signed_power = 0;
        let total_power: u64 = self.validators
            .iter()
            .filter(|(addr, v)| !self.slashed.contains(*addr) && v.voting_power > 0)
            .map(|(_, v)| v.voting_power)
            .sum();
        let mut seen_validators: HashSet<String> = HashSet::new();

        for vote in &commit.signatures {
            let addr = normalize_address(&vote.validator_address);
            if seen_validators.contains(&addr) {
                println!("Duplicate validator in commit");
                return None;
            }
            if self.slashed.contains(&addr) {
                println!("Slashed validator voted: {}", addr);
                return None;
            }
            if let Some(val) = self.validators.get(&addr) {
                if val.voting_power == 0 {
                    continue;
                }
                // Height/round/block hash consistency
                if vote.height != commit.height || vote.round != commit.round || vote.block_hash != commit.block_hash {
                    println!("Vote mismatch on height/round/block_hash");
                    return None;
                }
                // Verify Signature
                let msg = Self::compute_vote_sign_bytes(vote);
                if let Ok(valid) = MlDsa65::verify(&msg, &vote.signature, &val.public_key) {
                    if valid {
                        signed_power += val.voting_power;
                        seen_validators.insert(addr.clone());
                        // double-sign detection: same height/round different hash
                        if let Some(prev_hash) = self.observed_votes.get(&(vote.height, vote.round, addr.clone())) {
                            if prev_hash != &vote.block_hash {
                                println!("Slash: double-sign detected for validator {}", addr);
                                self.slashed.insert(addr.clone());
                                // Remove voting power
                                // (simple approach: set to zero)
                                if let Some(v) = self.validators.get_mut(&addr) {
                                    v.voting_power = 0;
                                }
                                return None;
                            }
                        }
                        self.observed_votes.insert((vote.height, vote.round, addr.clone()), vote.block_hash.clone());
                    }
                }
            }
        }

        // Check for 2/3 majority
        if total_power == 0 {
            None
        } else if signed_power > (total_power * 2 / 3) {
            Some(signed_power)
        } else {
            println!("Not enough power in commit: signed {}, total {}", signed_power, total_power);
            None
        }
    }

    fn commit_power_estimate(&self, commit: &Commit) -> u64 {
        commit.signatures.iter().fold(0u64, |acc, vote| {
            let addr = normalize_address(&vote.validator_address);
            if self.slashed.contains(&addr) {
                return acc;
            }
            if let Some(val) = self.validators.get(&addr) {
                if vote.height == commit.height && vote.round == commit.round && vote.block_hash == commit.block_hash {
                    return acc + val.voting_power;
                }
            }
            acc
        })
    }

    fn block_weight(&self, hash: &Vec<u8>) -> u128 {
        let work = self.work_by_hash.get(hash).copied().unwrap_or(0);
        let qc_power = self.blocks_by_hash.get(hash)
            .and_then(|b| b.last_commit.as_ref().map(|c| self.commit_power_estimate(c)))
            .unwrap_or(0);
        work + qc_power as u128
    }

    pub fn add_block(&mut self, block: Block) -> bool {
        let block_hash = compute_block_hash(&block);

        // Check parent work; if missing, stash as orphan
        if block.height > 0 && !self.work_by_hash.contains_key(&block.prev_hash) {
            self.orphans.entry(block.prev_hash.clone()).or_default().push(block);
            println!("Consensus: Block {} stored as orphan (missing parent).", block_hash.len());
            return false;
        }

        let parent_work = if block.height == 0 {
            0u128
        } else {
            *self.work_by_hash.get(&block.prev_hash).unwrap_or(&0)
        };

        self.blocks_by_hash.insert(block_hash.clone(), block.clone());
        self.work_by_hash.insert(block_hash.clone(), parent_work + block.difficulty as u128);

        if !self.verify_block(&block) {
            println!("Consensus: Block {} verification failed.", block.height);
            return false;
        }

        // Fork choice by total work plus QC power
        let tip_hash = compute_block_hash(self.chain.last().unwrap());
        let current_weight = self.block_weight(&tip_hash);
        let candidate_weight = self.block_weight(&block_hash);
        let current_height = self.chain.last().map(|b| b.height).unwrap_or(0);

        if candidate_weight > current_weight || (candidate_weight == current_weight && block.height > current_height) {
            if let Some(new_chain) = self.build_chain_from(block_hash.clone()) {
                println!("Consensus: Reorg/canonical switch to height {}", new_chain.last().map(|b| b.height).unwrap_or(0));
                self.chain = new_chain;
                let _ = self.save_to_disk("po8_chain.json");
            }
        }

        // Process any orphans that depended on this block
        if let Some(children) = self.orphans.remove(&block_hash) {
            for child in children {
                let _ = self.add_block(child);
            }
        }

        true
    }

    fn build_chain_from(&self, leaf_hash: Vec<u8>) -> Option<Vec<Block>> {
        let mut chain_rev: Vec<Block> = Vec::new();
        let mut cursor = Some(leaf_hash);
        while let Some(h) = cursor {
            let blk = self.blocks_by_hash.get(&h)?.clone();
            chain_rev.push(blk.clone());
            if blk.height == 0 {
                break;
            }
            cursor = Some(blk.prev_hash.clone());
        }
        // Verify genesis reached
        let last = chain_rev.last()?;
        if last.height != 0 {
            return None;
        }
        chain_rev.reverse();
        // Ensure heights and links are contiguous
        for w in chain_rev.windows(2) {
            if w[1].height != w[0].height + 1 {
                return None;
            }
            if w[1].prev_hash != compute_block_hash(&w[0]) {
                return None;
            }
        }
        Some(chain_rev)
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
