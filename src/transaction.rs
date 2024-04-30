use serde::{Deserialize, Serialize};

// Transaction struct represents a Bitcoin transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<Input>,
    pub vout: Vec<Output>,
}

// Input struct represents the input of a Bitcoin transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub txid: String,
    pub vout: u32,
    pub prevout: Prevout,
    pub scriptsig: Option<String>,
    pub scriptsig_asm: Option<String>,
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
    pub inner_redeemscript_asm: Option<String>,
}

// Prevout struct represents the previous output of a Bitcoin transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Prevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: u64,
}

// Output struct represents the output of a Bitcoin transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

// Block struct represents a Bitcoin block.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub version: i32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub timestamp: u32,
    pub bits: u32, // Difficulty target
    pub nonce: u32,
    pub transactions: Vec<Transaction>,
}

// BlockHeader struct represents the header of a Bitcoin block.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}
