use std::{
    collections::HashMap,
    fs::{self},
    path::Path,
};

use hex;

use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::transaction::Transaction;

type Result<T> = std::result::Result<T, failure::Error>;

// This function is used to hash the data using the RIPEMD160 algorithm
pub fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec()
}

// This function is used to hash the data using the SHA256 algorithm twice
pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

// This function is used to hash the data using the SHA256 algorithm
pub fn single_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// This function is used to verify the signature of a transaction
pub fn checksig_op(
    stack: &mut Vec<Vec<u8>>,
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
) -> Result<bool> {
    let dummy_pubkey: PublicKey = PublicKey::from_slice(
        &hex::decode("03bf68f1ce783df58a2459d549d5c655a1edc0f0cf4d79421fe978d358d79ee42a").unwrap(),
    )
    .unwrap();
    let dummy_signature: Signature = Signature::from_der(&hex::decode("304402205112f96bf7423703c221976603307f0e33913d39efc3344d68376fd2b8c0bd20022003ea588c06fa1a3e262e07ed6bf01a36f78741fe7bc6a91ff43c38a0a14e43fe").unwrap()).unwrap();

    let pubkey_bytes = stack.pop().unwrap();
    let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap_or(dummy_pubkey);
    let signature_bytes = stack.pop().expect("STACK UNDERFLOW");

    let sig = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1])
        .unwrap_or(dummy_signature);

    let sighash_type = signature_bytes.last().copied().expect("SIGHASH: MISSING") as u32;

    let mut trimmed_tx = trimmed_tx(tx.clone(), tx_input_index, input_type, sighash_type.clone())?;
    trimmed_tx.extend(&sighash_type.to_le_bytes());

    let trimmed_tx_hash = double_sha256(&trimmed_tx);
    let msg = Message::from_digest_slice(&trimmed_tx_hash).expect("PARSING: FAILED");

    let secp = Secp256k1::new();

    let mut result: bool = false;

    if secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
        result = true;
    }
    Ok(result)
}

// This function is used to verify the multisig operation of a transaction
pub fn checkmultisig_op(
    stack: &mut Vec<Vec<u8>>,
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
) -> Result<bool> {
    let dummy_pubkey: PublicKey = PublicKey::from_slice(
        &hex::decode("03bf68f1ce783df58a2459d549d5c655a1edc0f0cf4d79421fe978d358d79ee42a").unwrap(),
    )
    .unwrap();

    let dummy_signature: Signature = Signature::from_der(&hex::decode("304402205112f96bf7423703c221976603307f0e33913d39efc3344d68376fd2b8c0bd20022003ea588c06fa1a3e262e07ed6bf01a36f78741fe7bc6a91ff43c38a0a14e43fe").unwrap()).unwrap();

    let mut n_keys = 0;
    if let Some(item) = stack.pop() {
        if let Some(&byte) = item.first() {
            n_keys = byte as u8;
        }
    }

    let mut pubkeys: Vec<PublicKey> = Vec::new();

    for _ in 0..n_keys {
        let pubkey_bytes = stack.pop().expect("STACK UNDERFLOW: PUBKEY");
        pubkeys.push(PublicKey::from_slice(&pubkey_bytes).unwrap_or(dummy_pubkey));
    }

    let mut n_signatures = 0;
    if let Some(item) = stack.pop() {
        if let Some(&byte) = item.first() {
            n_signatures = byte as u8;
        }
    }

    let mut signatures: Vec<(Signature, u32)> = Vec::new();

    for _ in 0..n_signatures {
        let signature_bytes = stack.pop().expect("STACK UNDERFLOW: SIGNATURES");

        let sighash_type = signature_bytes.last().copied().expect("SIGHASH: MISSING") as u32;
        signatures.push((
            Signature::from_der(&signature_bytes[..&signature_bytes.len() - 1])
                .unwrap_or(dummy_signature),
            sighash_type,
        ));
    }

    let secp = Secp256k1::new();
    let mut valid_sig_count = 0;

    for (sig, sighash) in signatures {
        let mut trimmed_tx = trimmed_tx(tx.clone(), tx_input_index, input_type, sighash.clone())?;
        trimmed_tx.extend(&sighash.to_le_bytes());

        let trimmed_tx_hash = double_sha256(&trimmed_tx);
        let msg = Message::from_digest_slice(&trimmed_tx_hash).expect("PARSING: FAILED");

        for pk in &pubkeys {
            if secp.verify_ecdsa(&msg, &sig, pk).is_ok() {
                valid_sig_count += 1;
                break;
            }
        }
    }
    let mut result: bool = false;

    if valid_sig_count == n_signatures {
        result = true;
    }
    Ok(result)
}

// This function is used to trim the transaction
pub fn trimmed_tx(
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
    sighash_type: u32,
) -> Result<Vec<u8>> {
    let mut trimmed_tx: Vec<u8> = Vec::new();

    if sighash_type == 01 {
        if input_type == "NON_SEGWIT" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            trimmed_tx.push(tx.vin.len() as u8);

            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed =
                    hex::decode(&tx.vin[input_index].txid).expect("DECODING: FAILED");
                txid_bytes_reversed.reverse();

                trimmed_tx.extend_from_slice(&txid_bytes_reversed);
                trimmed_tx.extend(&tx.vin[input_index].vout.to_le_bytes());

                if input_index == tx_input_index {
                    let scriptsig_asm = tx.vin[input_index]
                        .scriptsig_asm
                        .clone()
                        .unwrap_or("SCRIPT SIG ASM: MISSING".to_string());

                    let scriptsig_asm_slices: Vec<&str> =
                        scriptsig_asm.split_whitespace().collect();

                    let redeem_script = scriptsig_asm_slices
                        .last()
                        .cloned()
                        .expect("STACK UNDERFLOW");

                    let redeem_script_bytes = hex::decode(redeem_script)?;

                    trimmed_tx.push(redeem_script_bytes.len().try_into()?);
                    trimmed_tx.extend_from_slice(&redeem_script_bytes);
                } else {
                    trimmed_tx.push(0 as u8);
                }
                trimmed_tx.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }

            trimmed_tx.push(tx.vout.len() as u8);

            for tx_ouput in tx.vout.iter() {
                let script_pubkey_bytes =
                    hex::decode(tx_ouput.scriptpubkey.clone()).expect("DECODING FAILED");

                trimmed_tx.extend(tx_ouput.value.to_le_bytes());
                trimmed_tx.push(script_pubkey_bytes.len().try_into()?);
                trimmed_tx.extend_from_slice(&script_pubkey_bytes);
            }
            trimmed_tx.extend(&tx.locktime.to_le_bytes());
        }

        if input_type == "P2SH-P2WPKH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            let inner_redeemscript_asm = tx.vin[tx_input_index]
                .inner_redeemscript_asm
                .clone()
                .unwrap_or("REDEEM SCRIPT: MISSING".to_string());

            let inner_redeemscript_asm_slices: Vec<&str> =
                inner_redeemscript_asm.split_whitespace().collect();
            let redeem_script = inner_redeemscript_asm_slices
                .last()
                .cloned()
                .unwrap_or("REDEEM SCRIPT: MISSING");

            let scrip_code = format!("{}{}{}", "1976a914", redeem_script, "88ac");
            let script_code_bytes = hex::decode(&scrip_code)?;

            trimmed_tx.extend_from_slice(&script_code_bytes);

            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2SH-P2WSH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            let witness_script_hex = tx.vin[tx_input_index]
                .witness
                .clone()
                .expect("WITNESS: MISSING")
                .last()
                .cloned()
                .expect("WITNESS SCRIPT: MISSING");

            let script_code_bytes = hex::decode(&witness_script_hex)?;

            trimmed_tx.push(script_code_bytes.len().try_into()?);
            trimmed_tx.extend_from_slice(&script_code_bytes);

            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2WPKH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

            let scriptpubkey_slices: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

            let pubkey_hash = scriptpubkey_slices
                .last()
                .cloned()
                .unwrap_or("SCRIPT PUB KEY: MISSING");
            let script_code_hex = format!("{}{}{}", "1976a914", pubkey_hash, "88ac");

            let script_code_bytes = hex::decode(&script_code_hex)?;

            trimmed_tx.extend_from_slice(&script_code_bytes);

            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2WSH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            let witness = tx.vin[tx_input_index].witness.clone().unwrap();

            let witness_script = witness.last().cloned().unwrap();

            let script_code_bytes = hex::decode(&witness_script)?;

            trimmed_tx.push(script_code_bytes.len().try_into()?);
            trimmed_tx.extend_from_slice(&script_code_bytes);

            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }
    }
    Ok(trimmed_tx)
}

// This function is used to verify the transaction
pub fn tx_verifier(tx: Transaction) -> Result<bool> {
    let _p2pkh = "p2pkh".to_string();
    let _p2sh = "p2sh".to_string();
    let _p2wpkh = "v0_p2wpkh".to_string();
    let _p2wsh = "v0_p2wsh".to_string();
    let _p2tr = "v1_p2tr".to_string();

    let tx_type = tx.vin[0].prevout.scriptpubkey_type.clone();
    let mut v_result = false;

    if gas_fees_check(&tx) != true {
        return Ok(false);
    }

    for input_index in 0..tx.vin.len() {
        if tx.vin[input_index].prevout.scriptpubkey_type != tx_type {
            return Ok(false);
        }
    }

    if tx_type == _p2pkh {
        for input_index in 0..tx.vin.len() {
            match p2pkh_input_verification(tx.clone(), input_index) {
                Ok(false) => {
                    return Ok(false);
                }
                Ok(true) => {
                    v_result = true;
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }
    }

    if tx_type == _p2wpkh {
        for input_index in 0..tx.vin.len() {
            match p2wpkh_input_verification(input_index, tx.clone()) {
                Ok(false) => {
                    return Ok(false);
                }

                Ok(true) => {
                    v_result = true;
                }

                Err(_) => {
                    return Ok(false);
                }
            }
        }
    }
    if tx_type == _p2wsh {
        for input_index in 0..tx.vin.len() {
            match p2wsh_input_verification(input_index, tx.clone()) {
                Ok(false) => {
                    return Ok(false);
                }

                Ok(true) => {
                    v_result = true;
                }

                Err(_) => {
                    return Ok(false);
                }
            }
        }
    }
    if tx_type == _p2tr {
        for input in tx.vin.iter() {
            let witness = input.witness.clone().unwrap();
            for item in witness {
                let item_bytes = hex::decode(&item)?;
                if item_bytes.len() >= 255 {
                    return Ok(false);
                }
            }
        }

        v_result = true;
    }

    Ok(v_result)
}

// This function is used to check the gas fees of the transaction
fn gas_fees_check(tx: &Transaction) -> bool {
    let mut s_sats: u64 = 0;
    let mut r_sats: u64 = 0;

    for input_index in 0..tx.vin.len() {
        if tx.vin[input_index].prevout.value <= 0 {
            return false;
        }
        s_sats += tx.vin[input_index].prevout.value;
    }

    for output_index in 0..tx.vout.len() {
        if tx.vout[output_index].value <= 0 {
            return false;
        }
        r_sats += tx.vout[output_index].value;
    }

    if s_sats - r_sats < 1500 {
        return false;
    } else {
        return true;
    }
}

// This function is used to verify all transactions
pub fn verify_all_tx() -> Result<()> {
    let mempool_dir = "./mempool";

    let mut spends: HashMap<String, String> = HashMap::new();

    'outer: for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            match fs::read_to_string(path) {
                Ok(contents) => match serde_json::from_str::<Transaction>(&contents) {
                    Ok(transaction) => {
                        for input in &transaction.vin {
                            let input_key = format!("{}{}", input.txid, input.vout);

                            match spends.get(&input_key) {
                                Some(existing_txid)
                                    if path.display().to_string() != *existing_txid =>
                                {
                                    continue 'outer;
                                }
                                _ => {
                                    spends.insert(input_key, path.display().to_string());
                                }
                            }
                        }

                        let result = tx_verifier(transaction)?;
                        if result == true {
                            if let Some(filename) = path.file_name() {
                                let valid_mempool_dir = Path::new("./validated");
                                let destination_path = valid_mempool_dir.join(filename);
                                fs::copy(&path, &destination_path)?;
                            }
                        }
                    }
                    Err(_e) => {}
                },
                Err(_e) => {}
            }
        }
    }
    Ok(())
}

// This function is used to validate the block header
pub fn p2pkh_input_verification(tx: Transaction, tx_input_index: usize) -> Result<bool> {
    Ok(execute_script(
        tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone(),
        match tx.vin[tx_input_index].scriptsig_asm.clone() {
            Some(value) => value,
            None => {
                return Ok(false);
            }
        },
        tx,
        tx_input_index,
    ))
}

// This function is used to execute the script
fn execute_script(
    scriptpubkey_asm: String,
    scriptsig_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> bool {
    let sigscript_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    let sig = hex::decode(*sigscript_asm_slices.get(1).expect("Signature missing"))
        .expect("Failed to decode signature");
    let pubkey = hex::decode(*sigscript_asm_slices.get(3).expect("Public key missing"))
        .expect("Failed to decode public key");

    let mut stack: Vec<Vec<u8>> = Vec::new();

    stack.push(sig);
    stack.push(pubkey);

    let op_codes: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

    for op_code in op_codes.iter() {
        match *op_code {
            "OP_DUP" => {
                let top = stack.last().cloned().expect("STACK UNDEFLOW: OP_DUP");
                stack.push(top);
            }
            "OP_HASH160" => {
                let top = stack.pop().expect("STACK UNDERFLOW: OP_HASH160");
                let hash = hash160(&top);
                stack.push(hash);
            }
            "OP_PUSHBYTES_20" => {
                continue;
            }
            _ => {
                if op_code.len() == 40 {
                    stack.push(hex::decode(op_code).unwrap());
                } else if *op_code == "OP_EQUALVERIFY" {
                    let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");
                    let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");

                    if a != b {
                        return false;
                    }
                } else if *op_code == "OP_CHECKSIG" {
                    let result = checksig_op_p2pkh(&tx, tx_input_index);

                    if result == true {
                        continue;
                    } else {
                        return false;
                    }
                }
            }
        }
    }
    true
}

// This function is used to verify the signature of a transaction
fn checksig_op_p2pkh(tx: &Transaction, tx_input_index: usize) -> bool {
    let mut trimmed_tx = Vec::new();

    trimmed_tx.extend(&tx.version.to_le_bytes());
    trimmed_tx.push(tx.vin.len() as u8);

    for input_index in 0..tx.vin.len() {
        let mut txid_bytes_reversed =
            hex::decode(&tx.vin[input_index].txid).expect("DECODING FAILED");

        txid_bytes_reversed.reverse();

        trimmed_tx.extend_from_slice(&txid_bytes_reversed);
        trimmed_tx.extend(&tx.vin[input_index].vout.to_le_bytes());

        if input_index == tx_input_index {
            let script_pub_key_bytes =
                hex::decode(&tx.vin[input_index].prevout.scriptpubkey).expect("DECODING FAILED");
            trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap());
            trimmed_tx.extend_from_slice(&script_pub_key_bytes);
        } else {
            trimmed_tx.push(0 as u8);
        }

        trimmed_tx.extend(&tx.vin[input_index].sequence.to_le_bytes());
    }

    trimmed_tx.push(tx.vout.len() as u8);

    for tx_ouput in tx.vout.iter() {
        let script_pub_key_bytes =
            hex::decode(tx_ouput.scriptpubkey.clone()).expect("DECODING FAILED");

        trimmed_tx.extend(tx_ouput.value.to_le_bytes());
        trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap());
        trimmed_tx.extend_from_slice(&script_pub_key_bytes);
    }

    trimmed_tx.extend(&tx.locktime.to_le_bytes());

    if let Some(sighash_type) = extract_sighash_type(
        tx.vin[tx_input_index]
            .scriptsig_asm
            .clone()
            .expect("SCRIPT SIG ASM: MISSING"),
    ) {
        trimmed_tx.extend(&sighash_type.to_le_bytes());
    }

    let scriptsig_asm = tx.vin[tx_input_index]
        .scriptsig_asm
        .clone()
        .expect("SCRIPT SIG ASM: MISSING");
    let scriptsig_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    let signature = scriptsig_asm_slices[1];
    let pubkey = scriptsig_asm_slices[3];

    let trimmed_tx_hash = double_sha256(&trimmed_tx);
    let signature_bytes = hex::decode(signature).expect("DECODING: FAILED");
    let pubkey_bytes = hex::decode(pubkey).expect("DECODING: FAILED");

    let secp = Secp256k1::new();
    let public_key = PublicKey::from_slice(&pubkey_bytes).expect("ERROR PARSING: PUBLIC KEY");
    let signature = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1]).unwrap();

    let message =
        Message::from_digest_slice(&trimmed_tx_hash).expect("ERROR CREATING MESSAGE FROM TX_HASH");

    match secp.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => {
            return true;
        }
        Err(_) => return false,
    }
}

// This function is used to extract the sighash type
fn extract_sighash_type(scriptsig_asm: String) -> Option<u32> {
    Some(
        (hex::decode(
            scriptsig_asm
                .split_whitespace()
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap(),
        )
        .ok()?)
        .last()
        .copied()
        .expect("NOT FOUND") as u32,
    )
}

// This function is used to verify the input of a transaction
pub fn p2wpkh_input_verification(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    Ok(p2wpkh_script_execution(
        match tx.vin[tx_input_index].witness.clone() {
            Some(value) => value,
            None => Vec::new(),
        },
        tx,
        tx_input_index,
    )?)
}

// This function is used to execute the script of a transaction
fn p2wpkh_script_execution(
    witness: Vec<String>,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 {
        return Ok(false);
    }

    if tx.vin[tx_input_index].scriptsig.clone().unwrap().len() != 0 {
        return Ok(false);
    }

    let input_type = "P2WPKH";

    let mut stack = witness
        .iter()
        .take(2)
        .map(|w| hex::decode(w).unwrap())
        .collect::<Vec<Vec<u8>>>();

    Ok(checksig_op(
        &mut stack,
        tx.clone(),
        tx_input_index,
        input_type,
    )?)
}

// This function is used to verify the input of a transaction
pub fn p2wsh_input_verification(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    Ok(p2wsh_script_execution(witness, tx, tx_input_index)?)
}

// This function is used to execute the script of a transaction
fn p2wsh_script_execution(
    witness: Vec<String>,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 {
        return Ok(false);
    }

    let input_type = "P2WSH";
    let mut script_result = false;

    let mut stack: Vec<Vec<u8>> = witness
        .iter()
        .take(witness.len() - 1)
        .map(|w| hex::decode(w).unwrap())
        .collect();

    let witness_script_bytes = hex::decode(&witness.last().cloned().expect("SCRIPT MISSING"))?;

    let witness_program = tx.vin[tx_input_index]
        .prevout
        .scriptpubkey_asm
        .split_whitespace()
        .collect::<Vec<&str>>()
        .last()
        .cloned()
        .unwrap_or("witness program: missing");

    let witness_program_bytes = hex::decode(&witness_program)?;
    let witnness_script_hash = single_sha256(&witness_script_bytes);

    if witnness_script_hash != witness_program_bytes {
        return Ok(false);
    }

    let mut index = 0;

    while index < witness_script_bytes.len() {
        let opcode = witness_script_bytes[index];
        index += 1;

        match opcode {
            _ if opcode <= 96 && opcode >= 81 => {
                stack.push(vec![opcode - 80]);
            }

            _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                if index + opcode as usize <= witness_script_bytes.len() {
                    let bytes = witness_script_bytes[index..index + opcode as usize].to_vec();
                    stack.push(bytes);
                    index += opcode as usize;
                }
            }

            174 => {
                let result_multisig =
                    checkmultisig_op(&mut stack, tx.clone(), tx_input_index, input_type)?;

                if result_multisig == true {
                    script_result = true;
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8])
                }
            }

            173 => {
                let result_singlesig =
                    checksig_op(&mut stack, tx.clone(), tx_input_index, input_type)?;

                if result_singlesig == true {
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8]);
                }

                let top = stack.pop().unwrap();
                if top == vec![1u8] {
                    script_result = true;
                    continue;
                } else {
                    return Ok(false);
                }
            }

            172 => {
                let sig_length = stack[stack.len() - 2].len();

                if sig_length <= 75 && sig_length >= 70 {
                    script_result =
                        checksig_op(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if script_result == true {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8])
                    }
                } else {
                    stack.push(vec![0u8]);
                }
            }

            169 => {
                let top = stack.pop().unwrap_or(vec![254u8]);
                stack.push(hash160(&top));
            }

            135 => {
                let a = stack.pop().unwrap_or(vec![254u8]);
                let b = stack.pop().unwrap_or(vec![254u8]);

                if a == b {
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8]);
                }
            }

            99 => {
                let top_stack_value = stack.pop().unwrap_or(vec![254u8]);
                let mut path = "else";
                let mut else_appeared = 0;
                if top_stack_value == vec![1u8] {
                    path = "if";
                }

                loop {
                    let opcode = witness_script_bytes[index];
                    index += 1;

                    match opcode {
                        117 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                stack.pop();
                            }
                        }

                        118 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.last().cloned().unwrap_or(vec![254u8]);
                                stack.push(top);
                            }
                        }

                        169 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.pop().unwrap_or(vec![254u8]);
                                stack.push(hash160(&top));
                            }
                        }

                        _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                            if index + opcode as usize <= witness_script_bytes.len() {
                                let bytes =
                                    witness_script_bytes[index..index + opcode as usize].to_vec();

                                if (path == "if" && else_appeared == 0)
                                    || (path == "else" && else_appeared == 1)
                                {
                                    stack.push(bytes);
                                }
                                index += opcode as usize;
                            }
                        }

                        136 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        135 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        105 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        103 => {
                            else_appeared = 1;
                        }

                        173 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let result_singlesig = checksig_op(
                                    &mut stack,
                                    tx.clone(),
                                    tx_input_index,
                                    input_type,
                                )?;

                                if result_singlesig == true {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                let top = stack.pop().unwrap();
                                if top == vec![1u8] {
                                    script_result = true;
                                    continue;
                                } else {
                                    return Ok(false);
                                }
                            }
                        }

                        172 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let sig_length = stack[stack.len() - 1].len();

                                if sig_length <= 75 && sig_length >= 70 {
                                    script_result = checksig_op(
                                        &mut stack,
                                        tx.clone(),
                                        tx_input_index,
                                        input_type,
                                    )?;

                                    if script_result == true {
                                        stack.push(vec![1u8]);
                                    } else {
                                        stack.push(vec![0u8])
                                    }
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        130 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let last_len =
                                    stack.last().cloned().unwrap_or(vec![254u8]).len() as u8;
                                stack.push(vec![last_len]);
                            }
                        }

                        104 => {
                            break;
                        }

                        _ => continue,
                    }
                }
            }

            100 => {
                let top_stack_value = stack.pop().unwrap_or(vec![254u8]);
                let mut path = "else";
                let mut else_appeared = 0;
                if top_stack_value == vec![0u8] {
                    path = "if";
                }

                loop {
                    let opcode = witness_script_bytes[index];
                    index += 1;

                    match opcode {
                        117 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                stack.pop();
                            }
                        }

                        118 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.last().cloned().unwrap_or(vec![254u8]);
                                stack.push(top);
                            }
                        }

                        169 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.pop().unwrap_or(vec![254u8]);
                                stack.push(hash160(&top));
                            }
                        }

                        _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                            if index + opcode as usize <= witness_script_bytes.len() {
                                let bytes =
                                    witness_script_bytes[index..index + opcode as usize].to_vec();

                                if (path == "if" && else_appeared == 0)
                                    || (path == "else" && else_appeared == 1)
                                {
                                    stack.push(bytes);
                                }
                                index += opcode as usize;
                            }
                        }

                        136 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        135 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        105 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        103 => {
                            else_appeared = 1;
                        }

                        173 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let result_singlesig = checksig_op(
                                    &mut stack,
                                    tx.clone(),
                                    tx_input_index,
                                    input_type,
                                )?;

                                if result_singlesig == true {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                let top = stack.pop().unwrap();
                                if top == vec![1u8] {
                                    script_result = true;
                                    continue;
                                } else {
                                    return Ok(false);
                                }
                            }
                        }

                        172 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let sig_length = stack[stack.len() - 1].len();

                                if sig_length <= 75 && sig_length >= 70 {
                                    script_result = checksig_op(
                                        &mut stack,
                                        tx.clone(),
                                        tx_input_index,
                                        input_type,
                                    )?;

                                    if script_result == true {
                                        stack.push(vec![1u8]);
                                    } else {
                                        stack.push(vec![0u8])
                                    }
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        130 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let last_len =
                                    stack.last().cloned().unwrap_or(vec![254u8]).len() as u8;
                                stack.push(vec![last_len]);
                            }
                        }

                        104 => {
                            break;
                        }

                        _ => continue,
                    }
                }
            }

            _ => continue,
        }
    }

    Ok(script_result)
}
