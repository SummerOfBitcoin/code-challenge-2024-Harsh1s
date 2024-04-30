use hex;

use crate::validator::checksig_op;

use crate::{error::Result, transaction::Transaction};

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
