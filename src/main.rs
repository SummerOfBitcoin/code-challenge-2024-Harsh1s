mod mine;
mod error;
mod transaction;
mod validate;

use crate::error::Result;
use crate::mine::mine_block;
use crate::validate::validate_transactions;

fn main() -> Result<()> {
    // Stage 1: Transaction Validation
    validate_transactions()?;
    println!("Transaction Verification: Completed");

    // Stage 2: Block Mining
    mine_block()?;
    println!("Block Mined: Success");

    Ok(())
}
