# SOLUTION.md

**Design Approach**

- **Bitcoin Fundamentals:** My approach was grounded in the core concepts of Bitcoin blocks, transactions, and their validation mechanisms:

  - **Block Structure:** Version, previous block hash, Merkle root of transactions, timestamp, difficulty target, and a nonce.
  - **Transaction Structure:** Inputs (referencing previous outputs), outputs (containing value and locking scripts), script types (P2PKH, P2WPKH, P2WSH).
  - **Script Execution:** Understanding stack-based execution, supported opcodes, and signature validation using the `secp256k1` library.
  - **Hashing:** SHA-256 (and RIPEMD-160 where applicable) for transaction IDs, Merkle root calculation, and Proof-of-Work.

- **Modular Design**
  - **Transaction Validation:** The `validator` module houses functions like `p2pkh_input_verification`, `p2wsh_input_verification`, etc. Each employs script execution logic and calls into `checksig_op` and `op_checkmultig`.
  - **Mempool Management:** A data structure to maintain valid transactions and logic in `verify_all_tx`.
  - **Block Assembly:** Functions responsible for selecting transactions, Merkle root construction, and compiling the block header.
  - **Proof-of-Work:** The iterative hashing process, using a dedicated function for efficient double-SHA-256 operations.

**Implementation Details**

- **Key Rust Structures:**

  - **`Transaction` struct:** Mirroring Bitcoin transaction fields with necessary type mappings for Rust.
  - **`Input` struct:** Capturing previous output details, scriptSig, witness, etc.
  - **`Output` struct:** Representing output locking scripts and values.

- **Script Execution (`validator` module):**

  - **Stack:** A Rust vector emulates the script execution stack.
  - **Opcode Handling:** Switch statements or pattern matching within `input_verification_...` functions for handling supported opcodes (e.g., `OP_DUP`, `OP_HASH160`, `OP_CHECKSIG`, etc.).
  - **Signature Verification:** The `checksig_op` function extracts signatures, public keys, and uses the `secp256k1::Signature` and `secp256k1::PublicKey` types.

- **Mempool and Block Construction**

  - **Transaction Selection:** The code has a mechanism for choosing transactions from the mempool and putting them inside valid-mempool folder after validating them.
  - **Merkle Root:** Implementation of a recursive Merkle tree building algorithm for transaction hash aggregation.

- **Proof-of-Work**
  - **Hashing:** Efficient double-SHA-256 implementation, optimized for the mining process.
  - **Difficulty Comparison:** Uses Rust's numeric types and comparison operators to check the calculated hash against the target.

**Results and Performance**

- **Block is created with following details**
  - Score: 101
  - Fee: 21619204
  - Weight: 3994072
  - Max Fee: 20616923
  - Max Weight: 4000000
  - Number of Transactions: 4472

**Conclusion**

This project deepened my understanding of Bitcoin's low-level mechanics.

**Potential Improvements**

- **Script Support Expansion:** Implement a broader range of opcodes to handle a wider variety of Bitcoin transactions.

- **Performance Optimization:** Investigate other projects and how they deal with performance issues.

**References**

- Mastering Bitcoin by Andreas Antonopoulos
- Bitcoin Developer Reference ([https://developer.bitcoin.org/](https://developer.bitcoin.org/))
- Bitcoin Wiki ([https://en.bitcoin.it/wiki/Main_Page](https://en.bitcoin.it/wiki/Main_Page))
