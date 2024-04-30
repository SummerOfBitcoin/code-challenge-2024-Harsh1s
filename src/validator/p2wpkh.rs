use hex;

use crate::validator::op_checksig;

use crate::{error::Result, transaction::Transaction};

pub fn input_verification_p2wpkh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    Ok(script_execution_p2wpkh(witness, tx, tx_input_index)?)
}

fn script_execution_p2wpkh(
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

    let mut stack = Vec::new();

    stack.push(hex::decode(&witness[0])?);
    stack.push(hex::decode(&witness[1])?);

    let script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

    Ok(script_result)
}
