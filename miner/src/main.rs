use num_bigint::BigUint;
use num_traits::Num;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
struct Transaction {
    version: u32,
    locktime: u32,
    txid: Option<String>,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vin {
    txid: String,
    vout: u32,
    prevout: Prevout,
    scriptsig: String,
    sequence: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Prevout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

fn load_transactions(folder_path: &str) -> Result<Vec<Transaction>, Box<dyn Error>> {
    let mut transactions = Vec::new();
    let paths = fs::read_dir(folder_path)?;

    for path in paths {
        let file_path = path?.path();
        let contents = fs::read_to_string(&file_path)?;
        let transaction: Transaction = serde_json::from_str(&contents)?;

        transactions.push(transaction);
    }

    Ok(transactions)
}

fn validate_transaction(transaction: &Transaction) -> bool {
    //TODO
    true
}

fn mine_block(
    transactions: Vec<Transaction>,
    difficulty_target: &str,
    max_block_size: usize,
) -> (String, Vec<String>) {
    let mut valid_transactions: Vec<Transaction> = Vec::new();

    for transaction in transactions {
        if validate_transaction(&transaction) {
            valid_transactions.push(transaction);
        }
    }

    valid_transactions.sort_by(|a, b| {
        let fee_rate_a = calculate_fee_rate(&a);
        let fee_rate_b = calculate_fee_rate(&b);
        fee_rate_b.partial_cmp(&fee_rate_a).unwrap()
    });

    let mut block_transactions: Vec<String> = Vec::new();
    let mut block_size = 0;
    let mut nonce = 0;

    let mut block_header = String::new();

    loop {
        let coinbase_tx = construct_coinbase_transaction();
        let mut block_data = coinbase_tx.clone();
        let block_nonce = nonce.to_string();
        let mut block_hash = String::new();

        for transaction in &valid_transactions {
            if let Some(txid) = &transaction.txid {
                let serialized_tx = serde_json::to_string(transaction).unwrap();
                if block_size + serialized_tx.len() <= max_block_size {
                    block_data.push_str(&serialized_tx);
                    block_size += serialized_tx.len();
                    block_transactions.push(txid.clone());
                } else {
                    break;
                }
            }
        }

        block_header = format!("{}{}{}", block_data, block_nonce, difficulty_target);
        block_hash = calculate_block_hash(&block_header);

        let block_hash_num = BigUint::from_str_radix(&block_hash, 16).unwrap();
        let difficulty_target_num = BigUint::from_str_radix(&difficulty_target, 16).unwrap();

        if block_hash_num < difficulty_target_num {
            break;
        }

        nonce += 1;
    }

    (block_header, block_transactions)
}

fn calculate_fee_rate(transaction: &Transaction) -> f64 {
    let input_sum: u64 = transaction.vin.iter().map(|vin| vin.prevout.value).sum();
    let output_sum: u64 = transaction.vout.iter().map(|vout| vout.value).sum();
    let fee = input_sum - output_sum;
    fee as f64 / transaction.vin.len() as f64
}

fn construct_coinbase_transaction() -> String {
    serde_json::to_string(&Transaction {
        version: 1,
        locktime: 0,
        txid: Some("coinbase_txid".to_string()),
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: "coinbase_script".to_string(),
            scriptpubkey_asm: "coinbase_script_asm".to_string(),
            scriptpubkey_type: "coinbase_script_type".to_string(),
            scriptpubkey_address: "coinbase_script_address".to_string(),
            value: 0,
        }],
    })
    .unwrap()
}

fn calculate_block_hash(block_data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(block_data);
    let hash_result = hasher.finalize();
    format!("{:x}", hash_result)
}

fn write_output(block_header: &str, block_transactions: Vec<String>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create("output.txt")?;
    file.write_all(block_header.as_bytes())?;
    file.write_all(b"\n")?;

    for txid in block_transactions {
        file.write_all(txid.as_bytes())?;
        file.write_all(b"\n")?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let transactions = load_transactions("../../mempool")?;
    let difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let max_block_size = 1000000;

    let (block_header, block_transactions) =
        mine_block(transactions, difficulty_target, max_block_size);
    write_output(&block_header, block_transactions)?;

    Ok(())
}
