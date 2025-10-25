# Documentation

There are 2 main contracts: `Wallet` to sign and send transactions, and `Node` to verify and mine blocks.

## [Wallet](https://github.com/nzmpi/BTConEVM/blob/master/src/Wallet.sol)

The `Wallet` contract is a "wallet" for signing and sending transactions. It supports P2PKH, P2SH, P2WPKH and P2WSH scripts.
It can also be used as a multisig wallet. 

To send a transaction, you need to provide `InputArgs` and `OutputArgs`. `InputArgs` contains input types, indices of the signing private keys, `txIds` and `vouts` for UTXOs to spend. `OutputArgs` contains output types, amounts, addresses and redeem/witness scripts.

For all transactions the wallet uses `version = 1`, `sequence = 0xffffffff`, `locktime = 0` and signs with `SIGHASH_ALL`. 

Also provides an address based on the script type, index or amount, and Mainnet or Testnet parameters. 

BEWARE: The `Wallet` contract is not a secure wallet. It is not recommended to use it for anything other than testing, because it keeps all the private keys in storage.

## [Node](https://github.com/nzmpi/BTConEVM/blob/master/src/Node.sol)

The `Node` contract is a node that verifies transactions and mines blocks. It supports P2PK, P2PKH, P2SH, P2WPKH and P2WSH scripts. When deployed, it creates the same genesis block that Bitcoin has.

To create a block it needs an array of transactions and an array of additional data, e.g. `redeemScript`. First it creates a coinbase transaction, then it validates the transactions and creates a block. 
Creating a block includes finding correct bits, which determines the target and difficulty, and if it needs an adjustment. Then calculates the merkle root of all transactions. And finally tries to find a nonce.

Validating a transaction includes checking if UTXOs exist, checking the signature by validating the script and collecting fees. All transactions must be created with `SIGHASH_ALL`.

Finding a nonce may fail (if `uint32` is not enough) or just run out of gas. This a downside of Solidity. But technically it's the same as in Bitcoin.

## Other Contracts

### [Script](https://github.com/nzmpi/BTConEVM/blob/master/src/Script.sol)

This contract emulates the Script language. It is called by the `Node` contract and expects `script`, which is `ScriptSig + ScriptPubKey`, `signatureHash` and `witness` for P2WPKH and P2WSH. If `script` fails, it reverts, otherwise nothing happens.

All supported opcodes can be found in the constructor.

## Libraries

### [Address](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Address.sol)

Gets the address from the hash, checks the checksum and gets the hash from the address.

### [Base58](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Base58.sol)

Takes care of Base58 encoding and decoding in Solidity.

### [Bech32](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Bech32.sol)

Takes care of Bech32 encoding and decoding in Solidity. Also verifies the checksum and gets the hash from the address.

### [ECBTC](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/ECBTC.sol)

A wrapper for elliptic curve operations using secp256k1 parameters.

### [SerialLib](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/SerialLib.sol)

Takes care of serializing and parsing public keys, signatures, private keys, transactions and blocks.

### [SigLib](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/SigLib.sol)

Takes care of signing and verifying signatures.

### [Utils](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Utils.sol)

Contains some helper functions, such as various hashing functions, conversion functions, etc.

### [Varint](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Varint.sol)

Takes care of varint encoding and decoding in Solidity.

## Other

### [Structs](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Structs.sol)

Contains structs that are used in the implementation.

### [Types](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/Types.sol)

Contains all supported script types.

### [EllipticCurve](https://github.com/nzmpi/BTConEVM/blob/master/src/lib/EllipticCurve.sol)

Library providing arithmetic operations over elliptic curves by Witnet Foundation.
