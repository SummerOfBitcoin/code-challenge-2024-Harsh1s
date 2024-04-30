mod block_mine;
mod error;
mod transaction;
mod validation_checks;

use crate::error::Result;

use crate::block_mine::block::valid_block_header;
use crate::validation_checks::all_transaction_verification;

fn main() -> Result<()> {
    all_transaction_verification()?;

    println!("TRANSACTION VERIFICATION: COMPLETED");

    valid_block_header()?;

    Ok(())
}
