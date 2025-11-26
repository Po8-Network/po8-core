// Re-export dependencies
pub use revm;

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use revm::primitives::{Address, U256, ExecutionResult, Output, TransactTo, Bytes, Precompile, PrecompileResult, PrecompileError, PrecompileOutput, PrecompileErrors};
use revm::db::{CacheDB, EmptyDB, Database};
use revm::Evm;
use revm::precompile::Precompiles;
use revm::ContextPrecompiles; // Assuming this exists or similar
use hex;
use po8_crypto::{MlDsa65, QuantumSigner};

pub struct EvmEngine {
    // In-memory database for EVM state (accounts, code, storage)
    pub db: Arc<Mutex<CacheDB<EmptyDB>>>,
}

impl EvmEngine {
    pub fn new() -> Self {
        let db = Arc::new(Mutex::new(CacheDB::new(EmptyDB::default())));
        Self { db }
    }

    pub fn execute_transaction(
        &mut self,
        caller: String,
        to: String,
        value_wei: u128,
        data: Vec<u8>,
    ) -> Result<String, String> {
        let caller_addr = Address::from_str(&caller.replace("0x", "")).map_err(|_| "Invalid caller address")?;
        let to_addr = if to.is_empty() || to == "0x" {
            None
        } else {
            Some(Address::from_str(&to.replace("0x", "")).map_err(|_| "Invalid to address")?)
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

    pub fn mint(&mut self, address: String, amount: u128) -> Result<(), String> {
        let addr = Address::from_str(&address.replace("0x", "")).map_err(|_| "Invalid address")?;
        let amount = U256::from(amount);

        let mut db = self.db.lock().unwrap();
        let mut account = db.basic(addr).map_err(|_| "Failed to load account")?.unwrap_or_default();
        
        account.balance += amount;
        db.insert_account_info(addr, account);
        
        Ok(())
    }

    pub fn get_balance(&self, address: String) -> Result<u128, String> {
        let addr = Address::from_str(&address.replace("0x", "")).map_err(|_| "Invalid address")?;
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
