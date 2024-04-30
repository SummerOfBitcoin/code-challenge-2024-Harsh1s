mod miner;
mod error;
mod transaction;
mod validator;

use crate::error::Result;

use crate::miner::block::valid_block_header;
use crate::validator::all_transaction_verification;

fn main() -> Result<()> {
    all_transaction_verification()?;

    println!("Transactions Verified!");

    valid_block_header()?;

    Ok(())
}
