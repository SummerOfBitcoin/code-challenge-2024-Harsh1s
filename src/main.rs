mod error;
mod miner;
mod transaction;
mod validator;

use crate::error::Result;

use crate::miner::block::block_header_validator;
use crate::validator::verify_all_tx;

fn main() -> Result<()> {
    verify_all_tx()?;

    println!("Transactions Verified!");

    block_header_validator()?;

    Ok(())
}
