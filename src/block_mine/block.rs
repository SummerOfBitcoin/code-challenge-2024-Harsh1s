use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::Write};

use num_bigint::BigUint;
use num_traits::Num;

use crate::{block_mine::serialise_tx::double_sha256, error::Result};

use super::{merkle_root::generate_roots, serialise_tx::create_txid_tx_map};

// Function to compact the target
fn compact_target(target_hex: &str) -> u32 {
    // Decode the target from hex
    let decoded_target = hex::decode(target_hex).expect("Invalid hex string");
    let mut target_slice = decoded_target.as_slice();

    // Remove leading zeros
    while let Some(&0) = target_slice.first() {
        target_slice = &target_slice[1..];
    }

    // Calculate the size and significant part of the target
    let size = target_slice.len() as u32;
    let (exp, significant) = if size <= 3 {
        (
            size,
            u32::from_be_bytes(
                [0; 1]
                    .iter()
                    .chain(target_slice.iter().chain(std::iter::repeat(&0)))
                    .take(4)
                    .cloned()
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap(),
            ),
        )
    } else {
        let significant_slice = &target_slice[0..3];
        let significant = u32::from_be_bytes(
            [0; 1]
                .iter()
                .chain(significant_slice.iter())
                .cloned()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        );
        (size, significant)
    };

    // Calculate the compact target
    let compact = if significant & 0x00800000 != 0 {
        (significant >> 8) | ((exp + 1) << 24)
    } else {
        significant | (exp << 24)
    };

    compact
}

// Function to check the block header
pub fn check_block_header() -> Result<()> {
    // Define the version number and encode it to hex
    let version_num: u32 = 4;
    let version = hex::encode(version_num.to_le_bytes());

    // Define the previous block hash
    let previous_block_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    // Create a map of transaction IDs to transactions
    let map = create_txid_tx_map()?;
    // Generate the merkle root, coinbase transaction, and list of transaction IDs
    let (merkel_root, coinbase_tx, _, txids) = generate_roots(map.clone())?;

    // Get the current time and convert it to a timestamp
    let current_time = SystemTime::now();
    let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap();
    let time_stamp_num = since_epoch.as_secs() as u32;
    let time_stamp = hex::encode(time_stamp_num.to_le_bytes());

    // Define the target and convert it to a number
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target_num = BigUint::from_str_radix(target, 16).expect("INVALID HEX IN THE BLOCK");
    // Compact the target
    let bits = compact_target(target);
    let bits_hex = format!("{:08x}", bits);
    let mut bits_in_bytes = hex::decode(&bits_hex)?;
    bits_in_bytes.reverse();
    let bits_le = hex::encode(bits_in_bytes);

    // Initialize the nonce
    let mut nonce: u32 = 0;

    let valid_header: String;

    // Loop until a valid nonce is found
    loop {
        // Encode the nonce to hex
        let nonce_hex = hex::encode(nonce.to_le_bytes());

        // Initialize the block header
        let mut block_header: String = String::new();

        // Add the version, previous block hash, merkle root, timestamp, bits, and nonce to the block header
        block_header.push_str(&version);
        block_header.push_str(&previous_block_hash);
        block_header.push_str(&merkel_root);
        block_header.push_str(&time_stamp);
        block_header.push_str(&bits_le);
        block_header.push_str(&nonce_hex);

        // Calculate the block hash
        let mut block_hash_bytes = double_sha256(&hex::decode(&block_header)?);
        block_hash_bytes.reverse();
        let block_hash = hex::encode(block_hash_bytes);

        // Convert the block hash to a number
        let block_hash_num =
            BigUint::from_str_radix(&block_hash, 16).expect("Invalid hex in block hash");

        // If the block hash is less than or equal to the target, a valid nonce has been found
        if block_hash_num <= target_num {
            println!("Valid nonce found: {}", nonce);
            valid_header = block_header;
            break;
        }

        // Increment the nonce
        nonce += 1;
    }

    // Create a file to write the block to
    let mut block_file = File::create("./output.txt")?;

    // Print the number of transactions
    println!("{}", txids.len());

    // Write the valid header and coinbase transaction to the file
    writeln!(block_file, "{}", valid_header)?;
    writeln!(block_file, "{}", coinbase_tx)?;

    // Write each transaction ID to the file
    for txid in txids {
        writeln!(block_file, "{}", txid)?;
    }

    Ok(())
}