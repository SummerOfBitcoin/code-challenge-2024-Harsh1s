use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::Write};

use num_bigint::BigUint;
use num_traits::Num;

use crate::{miner::serialise_tx::double_sha256, error::Result};

use super::{merkle_root::generate_roots, serialise_tx::create_txid_tx_map};

fn target_to_compact(target_hex: &str) -> u32 {
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

    let compact = if significant & 0x00800000 != 0 {
        (significant >> 8) | ((exp + 1) << 24)
    } else {
        significant | (exp << 24)
    };

    compact
}

pub fn valid_block_header() -> Result<()> {
    let version_int: u32 = 4;
    let version = hex::encode(version_int.to_le_bytes());

    let prev_block_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let map = create_txid_tx_map()?;
    let (merkel_root, coinbase_tx, _, txids) = generate_roots(map.clone())?;

    let current_time = SystemTime::now();
    let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap();
    let time_stamp_int = since_epoch.as_secs() as u32;
    let time_stamp = hex::encode(time_stamp_int.to_le_bytes());

    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target_int = BigUint::from_str_radix(target, 16).expect("INVALID HEX IN THE BLOCK");
    let bits = target_to_compact(target);
    let bits_hex = format!("{:08x}", bits);
    let mut bits_in_bytes = hex::decode(&bits_hex)?;
    bits_in_bytes.reverse();
    let bits_le = hex::encode(bits_in_bytes);

    let mut nonce: u32 = 0;

    let valid_block_header: String;

    loop {
        let nonce_hex = hex::encode(nonce.to_le_bytes());

        let mut block_header: String = String::new();

        block_header.push_str(&version);
        block_header.push_str(&prev_block_hash);
        block_header.push_str(&merkel_root);
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
            valid_block_header = block_header;
            break;
        }

        nonce += 1;
    }

    let mut block_file = File::create("./output.txt")?;

    println!("Number of Transactions: {}", txids.len());

    writeln!(block_file, "{}", valid_block_header)?;
    writeln!(block_file, "{}", coinbase_tx)?;

    for txid in txids {
        writeln!(block_file, "{}", txid)?;
    }

    Ok(())
}
