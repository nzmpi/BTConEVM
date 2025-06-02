# Bitcoin on the EVM (kind of)

An implementation of Bitcoin using only Solidity (and Yul). 

## Why?

Why not? The fact that I can do it is pretty cool.

## Architecture

It's almost a direct implementation of the Bitcoin protocol. 

It includes a node that verifies transactions and mines blocks, a wallet that can sign and send transactions and a lot of libraries to help with the implementation, such as the serialization library, the signature library, Base58 and Bech32, etc. The node supports `P2PK`, `P2PKH`, `P2SH`, `P2WPKH` and `P2WSH` scripts.

There are some differences either because of the limitations of Solidity or I was too lazy.

The main differences are:

    - The node verifies transactions created only with `SIGHASH_ALL`.
    - Bad script reverts everything.
    - Only Segwit version 0 is supported.
    - Only compressed public keys are used in the wallet.
    - OP_CODESEPARATOR not supported so some P2WSH transactions won't work.
    - Not all opcodes are supported.
    - No networking between nodes.

## Repository Structure

All contracts are held within the `src` folder. All the tests are held within the `test` folder.

For more info check [DOCS](https://github.com/nzmpi/BTConEVM/blob/master/DOCS.md).

## Usage

There is not much of a usage, but you can find real life examples in the `test` folder.


## Acknowledgements

This project was made with help from the following sources:

- [Learn me a bitcoin](https://learnmeabitcoin.com/).
- [Programming Bitcoin by O'Reilly](https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/).
- [Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page).
- [Opcode Explained](https://opcodeexplained.com).