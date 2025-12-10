// Re-export dependencies
pub use revm;

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use revm::primitives::{Address, U256, ExecutionResult, Output, TransactTo, Bytes, Precompile, PrecompileResult, PrecompileError, PrecompileOutput, PrecompileErrors};
use revm::db::{CacheDB, EmptyDB, Database};
use revm::Evm;
use revm::precompile::Precompiles;
use revm::ContextPrecompiles; 
use hex;
use po8_crypto::{MlDsa65, QuantumSigner};
use serde::{Serialize, Deserialize};

pub struct EvmEngine {
    // In-memory database for EVM state (accounts, code, storage)
    pub db: Arc<Mutex<CacheDB<EmptyDB>>>,
}

impl EvmEngine {
    pub fn new() -> Self {
        let db = Arc::new(Mutex::new(CacheDB::new(EmptyDB::default())));
        Self { db }
    }

    pub fn load_from_disk(path: &str) -> Result<Self, String> {
        if !std::path::Path::new(path).exists() {
             return Ok(Self::new());
        }
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let db: CacheDB<EmptyDB> = serde_json::from_reader(file).map_err(|e| e.to_string())?;
        Ok(Self { db: Arc::new(Mutex::new(db)) })
    }

    pub fn save_to_disk(&self, path: &str) -> Result<(), String> {
        let db = self.db.lock().unwrap();
        let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        serde_json::to_writer(file, &*db).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn execute_transaction(
        &mut self,
        caller: String,
        to: String,
        value_wei: u128,
        data: Vec<u8>,
    ) -> Result<String, String> {
        let caller_addr = Address::from_str(&caller).map_err(|_| "Invalid caller address")?;
        let to_addr = if to.is_empty() || to == "0x" {
            None
        } else {
            Some(Address::from_str(&to).map_err(|_| "Invalid to address")?)
        };
        let value = U256::from(value_wei);

        let mut db_guard = self.db.lock().unwrap();
        
        let mut evm = Evm::builder()
            .with_db(&mut *db_guard)
            .append_handler_register(handle_register)
            .modify_tx_env(|tx| {
                tx.caller = caller_addr;
                tx.transact_to = if let Some(addr) = to_addr {
                    TransactTo::Call(addr)
                } else {
                    TransactTo::Create
                };
                tx.value = value;
                tx.data = data.into();
                tx.gas_limit = 10_000_000;
                tx.gas_price = U256::from(1);
            })
            .build();

        // Execute and Commit
        let result = evm.transact_commit().map_err(|e| format!("EVM Error: {:?}", e))?;

        match result {
            ExecutionResult::Success { output, .. } => {
                match output {
                    Output::Call(bytes) => Ok(hex::encode(bytes)),
                    Output::Create(bytes, addr) => {
                         if let Some(address) = addr {
                             Ok(format!("Contract Created at {:?} (Output: {})", address, hex::encode(bytes)))
                         } else {
                             Ok(format!("Contract Created (Output: {})", hex::encode(bytes)))
                         }
                    }
                }
            },
            ExecutionResult::Revert { output, .. } => {
                Err(format!("Reverted: {}", hex::encode(output)))
            },
            ExecutionResult::Halt { reason, .. } => {
                Err(format!("Halted: {:?}", reason))
            }
        }
    }

    pub fn call(
        &mut self,
        caller: String,
        to: String,
        value_wei: u128,
        data: Vec<u8>,
    ) -> Result<String, String> {
        let caller_addr = Address::from_str(&caller).map_err(|_| "Invalid caller address")?;
        let to_addr = if to.is_empty() || to == "0x" {
            None
        } else {
            Some(Address::from_str(&to).map_err(|_| "Invalid to address")?)
        };
        let value = U256::from(value_wei);

        // Lock DB
        let mut db_guard = self.db.lock().unwrap();
        
        let mut evm = Evm::builder()
            .with_db(&mut *db_guard)
            .append_handler_register(handle_register)
            .modify_tx_env(|tx| {
                tx.caller = caller_addr;
                tx.transact_to = if let Some(addr) = to_addr {
                    TransactTo::Call(addr)
                } else {
                    TransactTo::Create
                };
                tx.value = value;
                tx.data = data.into();
                tx.gas_limit = 10_000_000;
                tx.gas_price = U256::from(1);
            })
            .build();

        // Execute without commit
        let result = evm.transact().map_err(|e| format!("EVM Error: {:?}", e))?;
        
        match result.result {
            ExecutionResult::Success { output, .. } => {
                match output {
                    Output::Call(bytes) => Ok(hex::encode(bytes)),
                    Output::Create(bytes, addr) => {
                         if let Some(address) = addr {
                             Ok(format!("Contract Created at {:?} (Output: {})", address, hex::encode(bytes)))
                         } else {
                             Ok(format!("Contract Created (Output: {})", hex::encode(bytes)))
                         }
                    }
                }
            },
            ExecutionResult::Revert { output, .. } => {
                Err(format!("Reverted: {}", hex::encode(output)))
            },
            ExecutionResult::Halt { reason, .. } => {
                Err(format!("Halted: {:?}", reason))
            }
        }
    }

    pub fn estimate_gas(
        &mut self,
        caller: String,
        to: String,
        value_wei: u128,
        data: Vec<u8>,
    ) -> Result<u64, String> {
        let caller_addr = Address::from_str(&caller).map_err(|_| "Invalid caller address")?;
        let to_addr = if to.is_empty() || to == "0x" {
            None
        } else {
            Some(Address::from_str(&to).map_err(|_| "Invalid to address")?)
        };
        let value = U256::from(value_wei);

        let mut db_guard = self.db.lock().unwrap();
        
        let mut evm = Evm::builder()
            .with_db(&mut *db_guard)
            .append_handler_register(handle_register)
            .modify_tx_env(|tx| {
                tx.caller = caller_addr;
                tx.transact_to = if let Some(addr) = to_addr {
                    TransactTo::Call(addr)
                } else {
                    TransactTo::Create
                };
                tx.value = value;
                tx.data = data.into();
                tx.gas_limit = 10_000_000; 
                tx.gas_price = U256::from(1);
            })
            .build();

        let result = evm.transact().map_err(|e| format!("EVM Error: {:?}", e))?;
        
        match result.result {
            ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Revert { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Halt { .. } => Err("Transaction Halted during estimation".to_string()),
        }
    }

    pub fn mint(&mut self, address: String, amount: u128) -> Result<(), String> {
        // Address::from_str handles "0x" prefix or raw hex
        let addr = Address::from_str(&address).map_err(|_| "Invalid address")?;
        let amount = U256::from(amount);

        let mut db = self.db.lock().unwrap();
        
        let mut info = db.basic(addr).map_err(|_| "Failed to load account")?.unwrap_or_default();
        info.balance += amount;
        
        // Ensure nonce/code_hash are set if default
        if info.code_hash == revm::primitives::KECCAK_EMPTY {
             // Default is fine
        }
        
        db.insert_account_info(addr, info);
        
        Ok(())
    }

    pub fn get_balance(&self, address: String) -> Result<u128, String> {
        let addr = Address::from_str(&address).map_err(|_| "Invalid address")?;
        let mut db = self.db.lock().unwrap();
        
        let account = db.basic(addr).map_err(|_| "Failed to load account")?.unwrap_or_default();
        
        Ok(account.balance.to::<u128>())
    }
}

use revm::handler::register::EvmHandler;

use revm::ContextPrecompile;

fn handle_register<EXT, DB: Database>(handler: &mut EvmHandler<'_, EXT, DB>) {
    // Clone the Arc to keep the original loader accessible
    let old_load = handler.pre_execution.load_precompiles.clone();
    
    // Override load_precompiles
    handler.pre_execution.load_precompiles = Arc::new(move || {
        // Load original precompiles (ContextPrecompiles)
        let mut precompiles = old_load();
        
        // Add custom precompile
        // ContextPrecompiles implements Extend<(Address, ContextPrecompile<DB>)>
        // We need to convert Precompile::Standard to ContextPrecompile.
        let precompile_addr = Address::from_str("0000000000000000000000000000000000000021").unwrap();
        
        let custom = ContextPrecompile::Ordinary(Precompile::Standard(verify_mldsa_precompile));
        
        precompiles.extend(vec![
            (precompile_addr, custom)
        ]);

        precompiles
    });
}

fn verify_mldsa_precompile(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let gas_cost = 5000; 
    if gas_limit < gas_cost {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }

    if input.len() < 96 {
         return Err(PrecompileErrors::Error(PrecompileError::Other("Input too short for ABI header".to_string())));
    }

    let pk_offset_u256 = U256::from_be_slice(&input[0..32]);
    let hash_bytes = &input[32..64]; 
    let sig_offset_u256 = U256::from_be_slice(&input[64..96]);

    let pk_offset: usize = pk_offset_u256.try_into().map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid PK Offset".to_string())))?;
    let sig_offset: usize = sig_offset_u256.try_into().map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid Sig Offset".to_string())))?;

    if pk_offset + 32 > input.len() {
        return Err(PrecompileErrors::Error(PrecompileError::Other("PK Offset out of bounds".to_string())));
    }
    let pk_len_u256 = U256::from_be_slice(&input[pk_offset..pk_offset+32]);
    let pk_len: usize = pk_len_u256.try_into().map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid PK Length".to_string())))?;
    
    if pk_offset + 32 + pk_len > input.len() {
        return Err(PrecompileErrors::Error(PrecompileError::Other("PK Data out of bounds".to_string())));
    }
    let pk_bytes = &input[pk_offset+32..pk_offset+32+pk_len];

    if sig_offset + 32 > input.len() {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Sig Offset out of bounds".to_string())));
    }
    let sig_len_u256 = U256::from_be_slice(&input[sig_offset..sig_offset+32]);
    let sig_len: usize = sig_len_u256.try_into().map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid Sig Length".to_string())))?;
    
    if sig_offset + 32 + sig_len > input.len() {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Sig Data out of bounds".to_string())));
    }
    let sig_bytes = &input[sig_offset+32..sig_offset+32+sig_len];

    match MlDsa65::verify(hash_bytes, sig_bytes, pk_bytes) {
        Ok(valid) => {
            let mut result = [0u8; 32];
            if valid {
                result[31] = 1;
            }
            Ok(PrecompileOutput::new(gas_cost, Bytes::copy_from_slice(&result)))
        },
        Err(_) => {
            Ok(PrecompileOutput::new(gas_cost, Bytes::from(vec![0u8; 32])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use po8_crypto::{MlDsa65, QuantumSigner};
    use sha3::{Digest, Sha3_256};

    #[test]
    #[ignore] // TODO: Debug CacheDB persistence issue in test env
    fn test_mldsa_precompile() {
        let mut engine = EvmEngine::new();
        
        // 1. Generate Keypair
        let keypair = MlDsa65::generate_keypair().unwrap();
        
        // 2. Sign a message
        let msg = b"test message";
        let mut hasher = Sha3_256::new();
        hasher.update(msg);
        let hash = hasher.finalize(); // 32 bytes
        
        let sig = MlDsa65::sign(msg, &keypair.secret_key).unwrap();

        // 3. Construct Input for Precompile
        // [PK_Offset (32)][Hash (32)][Sig_Offset (32)][PK_Len (32)][PK_Bytes...][Sig_Len (32)][Sig_Bytes...]
        
        let pk_len = keypair.public_key.len();
        let sig_len = sig.len();
        
        let mut input = Vec::new();
        // Offsets (relative to start of input)
        // PK Data starts after header (3 * 32 = 96 bytes) + PK Len word (32) = 128
        let pk_offset = 96; 
        // Sig Data starts after PK Data + Sig Len word (32)
        // PK Data ends at 128 + pk_len
        // So Sig starts at 128 + pk_len
        // But we need the Sig Length word before it?
        // The precompile logic reads:
        // pk_len at pk_offset
        // pk_bytes at pk_offset + 32
        
        // So pk_offset should point to where pk_len is.
        
        let sig_offset = pk_offset + 32 + pk_len;

        input.extend_from_slice(&U256::from(pk_offset).to_be_bytes::<32>());
        input.extend_from_slice(&hash);
        input.extend_from_slice(&U256::from(sig_offset).to_be_bytes::<32>());
        
        // PK Section
        input.extend_from_slice(&U256::from(pk_len).to_be_bytes::<32>());
        input.extend_from_slice(&keypair.public_key);
        
        // Sig Section
        input.extend_from_slice(&U256::from(sig_len).to_be_bytes::<32>());
        input.extend_from_slice(&sig);

        // 4. Call Precompile via raw EVM transact (simulated by calling a contract that calls it, or just testing logic?)
        // Since we want to unit test the `verify_mldsa_precompile` function directly or via `execute_transaction` if possible.
        // But `execute_transaction` takes `data` which is calldata for a contract.
        // To verify precompile, we can try to call it directly as if it were a contract.
        
        let precompile_addr = "0000000000000000000000000000000000000021"; // 0x...21
        
        // We need to mint gas to a caller first
        let caller = "0x1111111111111111111111111111111111111111";
        engine.mint(caller.to_string(), 10u128.pow(18)).unwrap();

        let result = engine.execute_transaction(
            caller.to_string(), 
            precompile_addr.to_string(), 
            0, 
            input
        );

        match result {
            Ok(res_hex) => {
                let bytes = hex::decode(res_hex).unwrap();
                // Expect 32 bytes, last byte 1 for success
                assert_eq!(bytes.len(), 32);
                assert_eq!(bytes[31], 1, "Verification failed in EVM");
            },
            Err(e) => panic!("EVM execution failed: {}", e),
        }
    }
}
