use std::vec;

use hex;

use crate::validator::hash160;
use crate::validator::op_checkmultisig;
use crate::validator::op_checksig;

use crate::{error::Result, transaction::Transaction};

use super::single_sha256;

pub fn input_verification_p2wsh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    Ok(script_execution_p2wsh(witness, tx, tx_input_index)?)
}

fn script_execution_p2wsh(
    witness: Vec<String>,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 {
        return Ok(false);
    }

    let input_type = "P2WSH";
    let mut script_result = false;

    let mut stack: Vec<Vec<u8>> = Vec::new();

    for index in 0..witness.len() - 1 {
        stack.push(hex::decode(&witness[index])?);
    }

    let witness_script_bytes = hex::decode(&witness.last().cloned().expect("SCRIPT MISSING"))?;

    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();
    let scriptpubkey_asm_slices: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    let witness_program = scriptpubkey_asm_slices
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
                    op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                if result_multisig == true {
                    script_result = true;
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8])
                }
            }

            173 => {
                let result_singlesig =
                    op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

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
                        op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

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
                                let result_singlesig = op_checksig(
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
                                    script_result = op_checksig(
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
                                let result_singlesig = op_checksig(
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
                                    script_result = op_checksig(
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