use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::Write};

use num_bigint::BigUint;
use num_traits::Num;

use sha2::{Digest, Sha256};
use std::fs;
use walkdir::WalkDir;

use crate::transaction::Transaction;

type Result<T> = std::result::Result<T, failure::Error>;

// This function is used to convert the target to a compact target
fn compact_target(target_hex: &str) -> u32 {
    let target_bytes = hex::decode(target_hex).expect("Invalid hex string");
    let mut target_bytes = target_bytes.as_slice();

    while let Some(&0) = target_bytes.first() {
        target_bytes = &target_bytes[1..];
    }

    let size = target_bytes.len() as u32;
    let (exp, significant) = if size <= 3 {
        (
            size,
            u32::from_be_bytes(
                [0; 1]
                    .iter()
                    .chain(target_bytes.iter().chain(std::iter::repeat(&0)))
                    .take(4)
                    .cloned()
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap(),
            ),
        )
    } else {
        let significant_bytes = &target_bytes[0..3];
        let significant = u32::from_be_bytes(
            [0; 1]
                .iter()
                .chain(significant_bytes.iter())
                .cloned()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        );
        (size, significant)
    };

    if significant & 0x00800000 != 0 {
        (significant >> 8) | ((exp + 1) << 24)
    } else {
        significant | (exp << 24)
    }
}

// This function is used to validate the block header
pub fn block_header_validator() -> Result<()> {
    let version_int: u32 = 4;
    let version = hex::encode(version_int.to_le_bytes());

    let prev_block_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let map = map_txid_to_tx()?;
    let (merkle_root, coinbase_tx, _, txids) = roots_generator(map.clone())?;

    let current_time = SystemTime::now();
    let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap();
    let time_stamp_int = since_epoch.as_secs() as u32;
    let time_stamp = hex::encode(time_stamp_int.to_le_bytes());

    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target_int = BigUint::from_str_radix(target, 16).expect("INVALID HEX IN THE BLOCK");

    let mut bits_in_bytes = hex::decode(format!("{:08x}", compact_target(target)))?;
    bits_in_bytes.reverse();
    let bits_le = hex::encode(bits_in_bytes);

    let mut nonce: u32 = 0;

    let block_header_validator: String;

    loop {
        let nonce_hex = hex::encode(nonce.to_le_bytes());

        let mut block_header: String = String::new();

        block_header.push_str(&version);
        block_header.push_str(&prev_block_hash);
        block_header.push_str(&merkle_root);
        block_header.push_str(&time_stamp);
        block_header.push_str(&bits_le);
        block_header.push_str(&nonce_hex);

        let mut block_hash_bytes = double_sha256(&hex::decode(&block_header)?);
        block_hash_bytes.reverse();

        let block_hash = hex::encode(block_hash_bytes);

        let block_hash_int =
            BigUint::from_str_radix(&block_hash, 16).expect("Invalid hex in block hash");

        if block_hash_int <= target_int {
            println!("Valid nonce found: {}", nonce);
            block_header_validator = block_header;
            break;
        }

        nonce += 1;
    }

    let mut block_file = File::create("./output.txt")?;

    println!("Number of Transactions: {}", txids.len());

    writeln!(block_file, "{}", block_header_validator)?;
    writeln!(block_file, "{}", coinbase_tx)?;

    for txid in txids {
        writeln!(block_file, "{}", txid)?;
    }

    Ok(())
}

// This function is used to generate the merkle root, coinbase transaction and txids
pub fn roots_generator(
    map: Vec<(String, Transaction, String, usize, u64)>,
) -> Result<(String, String, String, Vec<String>)> {
    let tx_weight_limit = 3993000;
    let mut current_tx_weight = 0;
    let mut txids: Vec<String> = Vec::new();
    let mut wtxids: Vec<String> = Vec::new();
    let mut block_subsidy = 0;

    wtxids.push("0000000000000000000000000000000000000000000000000000000000000000".to_string());

    for (txid, _, wtxid, weight, fees) in map {
        if current_tx_weight >= tx_weight_limit {
            break;
        }
        current_tx_weight += weight;
        block_subsidy += fees;

        txids.push(txid);
        wtxids.push(wtxid);
    }

    let witness_root_hash = merkle_root(wtxids)?;

    let (coinbase_tx, txid_coinbase_tx) = coinbase_creator(witness_root_hash, block_subsidy)?;

    let mut coinbase_txid_bytes = double_sha256(&hex::decode(&txid_coinbase_tx)?);
    coinbase_txid_bytes.reverse();

    let coinbase_txid = hex::encode(coinbase_txid_bytes);

    txids.insert(0, coinbase_txid.clone());

    let merkle_root = merkle_root(txids.clone())?;

    Ok((merkle_root, coinbase_tx, coinbase_txid, txids))
}

// This function is used to generate the merkle root
fn merkle_root(txids: Vec<String>) -> Result<String> {
    let mut txids_natural: Vec<String> = Vec::new();

    for txid in txids.iter() {
        let mut txid_bytes = hex::decode(txid)?;
        txid_bytes.reverse();

        txids_natural.push(hex::encode(txid_bytes));
    }

    while txids_natural.len() > 1 {
        let mut next_level = Vec::new();

        if txids_natural.len() % 2 != 0 {
            txids_natural.push(txids_natural.last().unwrap().clone());
        }

        for chunk in txids_natural.chunks(2) {
            match chunk {
                [one, two] => {
                    let concat = one.to_owned() + two;
                    next_level.push(hex::encode(double_sha256(&hex::decode(&concat)?)));
                }
                _ => unreachable!(),
            }
        }

        txids_natural = next_level;
    }

    Ok(txids_natural[0].clone())
}

// This function is used to create the coinbase transaction
pub fn coinbase_creator(witness_root_hash: String, block_subsidy: u64) -> Result<(String, String)> {
    let mut coinbase_tx = String::new();
    let mut txid_coinbase_tx = String::new();

    let block_amount = 650082296 + block_subsidy;

    let witness_reserved_value =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let witness_commit = format!("{}{}", witness_root_hash, witness_reserved_value);

    let wtxid_commit = hex::encode(double_sha256(&hex::decode(&witness_commit)?));

    let wtxid_commitment = format!("{}{}", "6a24aa21a9ed", wtxid_commit);

    coinbase_tx.push_str("01000000");
    txid_coinbase_tx.push_str("01000000");

    coinbase_tx.push_str("0001");

    coinbase_tx.push_str("01");
    txid_coinbase_tx.push_str("01");

    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    coinbase_tx.push_str("ffffffff");
    coinbase_tx.push_str("25");
    coinbase_tx
        .push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100");
    coinbase_tx.push_str("ffffffff");

    coinbase_tx.push_str("02");

    coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes()));
    coinbase_tx.push_str("19");
    coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    coinbase_tx.push_str("0000000000000000");
    coinbase_tx.push_str("26");
    coinbase_tx.push_str(&wtxid_commitment);

    txid_coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    txid_coinbase_tx.push_str("ffffffff");
    txid_coinbase_tx.push_str("25");
    txid_coinbase_tx
        .push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100");
    txid_coinbase_tx.push_str("ffffffff");

    txid_coinbase_tx.push_str("02");

    txid_coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes()));
    txid_coinbase_tx.push_str("19");
    txid_coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    txid_coinbase_tx.push_str("0000000000000000");
    txid_coinbase_tx.push_str("26");
    txid_coinbase_tx.push_str(&wtxid_commitment);

    coinbase_tx.push_str("01");
    coinbase_tx.push_str("20");
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");

    coinbase_tx.push_str("00000000");
    txid_coinbase_tx.push_str("00000000");

    Ok((coinbase_tx, txid_coinbase_tx))
}

// This function is used to double sha256 the data
pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

// This function is used to map the txid to the transaction
pub fn map_txid_to_tx() -> Result<Vec<(String, Transaction, String, usize, u64)>> {
    let v_mempool_dir = "./validated";
    let mut map: Vec<(String, Transaction, String, usize, u64)> = Vec::new();

    for entry in WalkDir::new(v_mempool_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            match fs::read_to_string(path) {
                Ok(contents) => match serde_json::from_str::<Transaction>(&contents) {
                    Ok(transaction) => {
                        let (result, serialised_tx, serialised_wtx, tx_weight, fees) =
                            serialise_tx(&transaction)?;

                        if result == true {
                            let mut txid = double_sha256(&serialised_tx);
                            let mut wtxid = double_sha256(&serialised_wtx);

                            txid.reverse();
                            wtxid.reverse();

                            let txid = hex::encode(txid);
                            let wtxid = hex::encode(wtxid);

                            let position = map
                                .iter()
                                .position(|(_, _, _, net_weight, gas_fees)| {
                                    fees / tx_weight as u64 > *gas_fees / (*net_weight as u64)
                                })
                                .unwrap_or(map.len());
                            map.insert(position, (txid, transaction, wtxid, tx_weight, fees));
                        }
                    }
                    Err(_e) => {}
                },
                Err(_e) => {}
            }
        }
    }

    Ok(map)
}

// This function is used to serialise the transaction
fn serialise_tx(tx: &Transaction) -> Result<(bool, Vec<u8>, Vec<u8>, usize, u64)> {
    let tx_type;
    if tx.vin[0].witness == None {
        tx_type = "LEGACY";
    } else {
        tx_type = "SEGWIT";
    }

    let fees = tx.vin.iter().map(|input| input.prevout.value).sum::<u64>()
        - tx.vout.iter().map(|output| output.value).sum::<u64>();

    let mut non_witness_bytes = 0;
    let mut witness_bytes = 0;

    let mut raw_tx: Vec<u8> = Vec::new();
    let mut raw_wtx: Vec<u8> = Vec::new();

    if tx_type == "LEGACY" {
        raw_tx.extend(tx.version.to_le_bytes());
        non_witness_bytes += 4;

        if tx.vin.len() >= 50 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }

        raw_tx.push(tx.vin.len().try_into()?);
        non_witness_bytes += 1;

        for input in tx.vin.iter() {
            let mut txid = hex::decode(&input.txid.clone())?;
            txid.reverse();

            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?;
            let script_sig_len = script_sig.len();

            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());
            raw_tx.push(script_sig.len().try_into()?);
            raw_tx.extend_from_slice(&script_sig);
            raw_tx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 32 + 4 + 1 + script_sig_len + 4;
        }

        if tx.vout.len() >= 200 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }

        raw_tx.push(tx.vout.len().try_into()?);

        non_witness_bytes += 1;

        for output in tx.vout.iter() {
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?;
            let scriptpubkey_len = scriptpubkey.len();

            raw_tx.extend(output.value.to_le_bytes());
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 8 + 1 + scriptpubkey_len;
        }

        raw_tx.extend(tx.locktime.to_le_bytes());
        non_witness_bytes += 4;

        raw_wtx = raw_tx.clone();
    } else {
        raw_tx.extend(tx.version.to_le_bytes());
        raw_wtx.extend(tx.version.to_le_bytes());

        non_witness_bytes += 4;

        let marker = 00;
        let flag = 01;
        raw_wtx.push(marker.try_into()?);
        raw_wtx.push(flag.try_into()?);

        witness_bytes += 1 + 1;

        if tx.vin.len() >= 200 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }
        raw_tx.push(tx.vin.len().try_into()?);
        raw_wtx.push(tx.vin.len().try_into()?);

        non_witness_bytes += 1;

        for input in tx.vin.iter() {
            let mut txid = hex::decode(&input.txid.clone())?;
            txid.reverse();

            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?;
            let script_sig_len = script_sig.len();

            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());

            raw_wtx.extend_from_slice(&txid);
            raw_wtx.extend(input.vout.to_le_bytes());

            non_witness_bytes += 32 + 4;

            if script_sig.len() >= 255 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0));
            }

            raw_tx.push(script_sig.len().try_into()?);
            raw_wtx.push(script_sig.len().try_into()?);

            non_witness_bytes += 1;

            if script_sig.len() != 0 {
                raw_tx.extend_from_slice(&script_sig);
                raw_wtx.extend_from_slice(&script_sig);

                non_witness_bytes += script_sig_len;
            }
            raw_tx.extend(input.sequence.to_le_bytes());
            raw_wtx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 4;
        }

        if tx.vout.len() >= 255 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }
        raw_tx.push(tx.vout.len().try_into()?);
        raw_wtx.push(tx.vout.len().try_into()?);

        non_witness_bytes += 1;

        for output in tx.vout.iter() {
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?;
            let scriptpubkey_len = scriptpubkey.len();

            raw_tx.extend(output.value.to_le_bytes());
            raw_wtx.extend(output.value.to_le_bytes());

            non_witness_bytes += 8;

            if scriptpubkey.len() >= 50 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0));
            }
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_wtx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);
            raw_wtx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 1 + scriptpubkey_len;
        }

        for input in tx.vin.iter() {
            let witness = input.witness.clone().unwrap();

            raw_wtx.push(witness.len().try_into()?);

            witness_bytes += 1;

            for item in witness {
                let item_bytes = hex::decode(&item)?;
                let item_bytes_len = item_bytes.len();
                raw_wtx.push(item_bytes.len().try_into()?);
                raw_wtx.extend_from_slice(&item_bytes);

                witness_bytes += 1 + item_bytes_len;
            }
        }

        raw_tx.extend(tx.locktime.to_le_bytes());
        raw_wtx.extend(tx.locktime.to_le_bytes());

        non_witness_bytes += 4;
    }

    let tx_weight = (non_witness_bytes * 4) + (witness_bytes);

    Ok((true, raw_tx, raw_wtx, tx_weight, fees))
}
