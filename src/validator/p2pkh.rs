use hex;
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::transaction::Transaction;

pub fn p2pkh_input_verification(tx: Transaction, tx_input_index: usize) -> Result<bool> {
    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() {
        Some(value) => value,
        None => {
            return Ok(false);
        }
    };

    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

    Ok(execute_script(
        scriptpubkey_asm,
        scriptsig_asm,
        tx,
        tx_input_index,
    ))
}

fn execute_script(
    scriptpubkey_asm: String,
    scriptsig_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> bool {
    let sigscript_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    let signature = *sigscript_asm_slices.get(1).expect("Signature missing");
    let pubkey = *sigscript_asm_slices.get(3).expect("Public key missing");

    let sig = hex::decode(signature).expect("Failed to decode signature");
    let pubkey = hex::decode(pubkey).expect("Failed to decode public key");

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
                    let result = checksig_op(&tx, tx_input_index);

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

fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec()
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

fn checksig_op(tx: &Transaction, tx_input_index: usize) -> bool {
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

fn extract_sighash_type(scriptsig_asm: String) -> Option<u32> {
    let scriptsig_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();
    let signature = scriptsig_slices[1];
    let sig_bytes = hex::decode(signature).ok()?;
    let sighash_type = sig_bytes.last().copied().expect("NOT FOUND") as u32;

    Some(sighash_type)
}
