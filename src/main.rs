mod miner;
mod transaction;
mod validator;

use crate::miner::block_header_validator;
use crate::validator::verify_all_tx;

type Result<T> = std::result::Result<T, failure::Error>;

fn main() -> Result<()> {
    // Verify all transactions
    verify_all_tx()?;
    // Validate block header
    block_header_validator()?;
    Ok(())
}
