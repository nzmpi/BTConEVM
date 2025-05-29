// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "./Script.sol";
import {SerialLib} from "./lib/SerialLib.sol";
import {Block, Transaction} from "./lib/Structs.sol";
import {ScriptType} from "./lib/Types.sol";
import "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

/**
 * @title Node
 * @notice Emulates a Bitcoin node
 * @dev Supports P2PK, P2PKH, P2SH, P2WPKH and P2WSH scripts
 * @author https://github.com/nzmpi
 */
contract Node {
    using SerialLib for *;
    using Utils for *;
    using Varint for uint256;

    bytes4 constant SIGHASH_ALL = hex"01000000";
    uint256 constant MAX_TIME = 2 weeks * 4;
    uint256 constant MIN_TIME = 2 weeks / 4;
    uint256 constant DEFAULT_TARGET = 0x00000000ffff0000000000000000000000000000000000000000000000000000;
    bytes4 constant DEFAULT_BITS = hex"1d00ffff";
    Script immutable script;
    uint256 _currentHeight = 1;
    bytes _coinbase =
        hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    bytes4 _blockVersion = hex"00000001";
    bytes4 _blockNonce = hex"9962e000";
    uint256 public collectedFees;

    mapping(bytes32 txId => Transaction) _transactions;
    mapping(uint256 height => Block) _blocks;
    mapping(bytes32 txId => mapping(bytes4 vout => bool unspent)) public UTXOs;

    error InvalidFee();
    error InvalidTxInputs();
    error NotSupported();
    error UTXOisSpent();

    constructor(Script _script) payable {
        script = _script;
        _currentHeight = 1;
        // genesis block
        Block storage genesis = _blocks[0];
        genesis.version = hex"00000001";
        genesis.timestamp = hex"495fab29";
        genesis.bits = DEFAULT_BITS;
        genesis.nonce = hex"7c2bac1d";
        genesis.merkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b;
        genesis.transactionHashes.push(_addCoinbaseTx());
    }

    /**
     * Validates transactions and creates a new block
     * @param transactions - Array of transactions
     * @param data - Array of additional data
     */
    function validate(Transaction[] calldata transactions, bytes[][] calldata data) external {
        if (transactions.length != data.length) revert InvalidTxInputs();
        bytes32[] memory transactionHashes = new bytes32[](transactions.length + 1);
        // the first transaction is always coinbase
        transactionHashes[0] = _addCoinbaseTx();
        for (uint256 i; i < transactions.length; ++i) {
            transactionHashes[i + 1] = _validateTx(transactions[i], data[i]);
        }
        uint256 height = _currentHeight;
        Block memory newBlock = Block({
            version: _blockVersion,
            timestamp: bytes4(uint32(block.timestamp)),
            bits: _getNewBits(height),
            nonce: _blockNonce,
            prevBlock: _blocks[height - 1].serializeBlockHeader().hash256().convertEndian(),
            merkleRoot: _getMerkleRoot(transactionHashes.convertEndian()).convertEndian(),
            transactionHashes: transactionHashes
        });
        _findNonce(newBlock);
        _blocks[height] = newBlock;
        ++_currentHeight;
    }

    /**
     * Gets the transaction by its id
     * @param txId - Id of the transaction
     */
    function getTransaction(bytes32 txId) external view returns (Transaction memory) {
        return _transactions[txId];
    }

    /**
     * Gets the block by its height
     * @param height - Height of the block
     */
    function getBlock(uint256 height) external view returns (Block memory) {
        return _blocks[height];
    }

    /**
     * Returns the target and difficulty of the block, based on it's bits
     * @dev if block is not found, returns (0, 0)
     * @param height - Height of the block
     * @return target - Target of the block
     * @return difficulty - Difficulty of the block
     */
    function getTargetAndDifficulty(uint256 height) external view returns (uint256 target, uint256 difficulty) {
        uint256 bits = uint32(_blocks[height].bits);
        if (bits == 0) return (0, 0);
        target = _getTarget(bits);
        difficulty = 0xffff * 256 ** (0x1d - 3) / target;
    }

    /**
     * Validates the transaction
     * @param _transaction - Transaction to validate
     * @param _data - Additional data, e.g. redeemScript
     * @dev data.length should be equal to transaction.inputs.length, even if empty
     */
    function _validateTx(Transaction calldata _transaction, bytes[] calldata _data) internal returns (bytes32 txId) {
        uint256 len = _transaction.inputs.length;
        if (len == 0 || len != _data.length) revert InvalidTxInputs();
        bytes4 vout;
        uint256 inputSum;
        for (uint256 i; i < len; ++i) {
            txId = _transaction.inputs[i].txId;
            vout = _transaction.inputs[i].vout;
            if (!UTXOs[txId][vout]) revert UTXOisSpent();
            delete UTXOs[txId][vout];
            inputSum += uint64(_transactions[txId].outputs[uint32(vout)].amount);
        }
        _verifySignature(_transaction, len, _data);
        len = _transaction.outputs.length;
        uint256 outputSum;
        for (uint256 i; i < len; ++i) {
            outputSum += uint64(_transaction.outputs[i].amount);
        }
        if (outputSum > inputSum) revert InvalidFee();
        collectedFees = collectedFees + inputSum - outputSum;

        txId = _transaction.serializeTransactionLegacy().hash256().convertEndian();
        _transactions[txId] = _transaction;
        for (uint256 i; i < _transaction.outputs.length; ++i) {
            UTXOs[txId][bytes4(uint32(i))] = true;
        }
    }

    /**
     * Adds the coinbase transaction
     * @return coinbaseTxId - Hash of the coinbase transaction
     */
    function _addCoinbaseTx() internal returns (bytes32 coinbaseTxId) {
        Transaction memory coinbaseTx = _coinbase.parseTransaction();
        coinbaseTxId = _coinbase.hash256().convertEndian();
        Transaction storage coinbaseTxStor = _transactions[coinbaseTxId];
        coinbaseTxStor.isSegwit = coinbaseTx.isSegwit;
        coinbaseTxStor.version = coinbaseTx.version;
        coinbaseTxStor.locktime = coinbaseTx.locktime;
        for (uint256 i; i < coinbaseTx.inputs.length; ++i) {
            coinbaseTxStor.inputs.push(coinbaseTx.inputs[i]);
        }
        for (uint256 i; i < coinbaseTx.outputs.length; ++i) {
            coinbaseTxStor.outputs.push(coinbaseTx.outputs[i]);
            UTXOs[coinbaseTxId][bytes4(uint32(i))] = true;
        }
    }

    /**
     * Verifies the signature
     * @param _transaction - Transaction
     * @param _len - Transaction input length
     * @param _data - Additional data, e.g redeemScript
     * @dev Reverts if script type is not supported or
     * script fails, if successful does nothing
     */
    function _verifySignature(Transaction calldata _transaction, uint256 _len, bytes[] calldata _data) internal {
        Transaction memory tempTx = _transaction;
        tempTx.isSegwit = false;
        for (uint256 i; i < _len; ++i) {
            tempTx.inputs[i].scriptSig = "";
        }

        // prepare the preimage for P2WPKH and P2WSH
        bytes memory preimageStart;
        bytes memory preimageEnd;
        if (_transaction.isSegwit) {
            for (uint256 i; i < _len; ++i) {
                // prevouts
                preimageStart = bytes.concat(
                    preimageStart,
                    bytes.concat(_transaction.inputs[i].txId).convertEndian(),
                    bytes.concat(_transaction.inputs[i].vout).convertEndian()
                );
                // sequences
                preimageEnd = bytes.concat(preimageEnd, bytes.concat(_transaction.inputs[i].sequence).convertEndian());
            }
            preimageStart = bytes.concat(
                bytes.concat(_transaction.version).convertEndian(), preimageStart.hash256(), preimageEnd.hash256()
            );

            uint256 len = _transaction.outputs.length;
            preimageEnd = "";
            for (uint256 i; i < len; ++i) {
                preimageEnd = bytes.concat(
                    preimageEnd,
                    bytes.concat(_transaction.outputs[i].amount).convertEndian(),
                    _transaction.outputs[i].scriptPubKey.length.toVarint(),
                    _transaction.outputs[i].scriptPubKey
                );
            }
            preimageEnd = bytes.concat(preimageEnd.hash256(), bytes.concat(_transaction.locktime).convertEndian());
        }

        bytes memory preimage;
        bytes memory scriptPubKey;
        ScriptType scriptType;
        for (uint256 i; i < _len; ++i) {
            scriptPubKey =
                _transactions[_transaction.inputs[i].txId].outputs[uint32(_transaction.inputs[i].vout)].scriptPubKey;
            scriptType = _getScriptType(scriptPubKey);
            if (scriptType == ScriptType.P2PK || scriptType == ScriptType.P2PKH) {
                tempTx.inputs[i].scriptSig = scriptPubKey;
                _execute(
                    bytes.concat(_transaction.inputs[i].scriptSig, scriptPubKey),
                    tempTx.serializeTransaction(),
                    new bytes[](0)
                );
            } else if (scriptType == ScriptType.P2SH) {
                tempTx.inputs[i].scriptSig = _data[i];
                _execute(
                    bytes.concat(_transaction.inputs[i].scriptSig, scriptPubKey),
                    tempTx.serializeTransaction(),
                    new bytes[](0)
                );
            } else if (scriptType == ScriptType.P2WPKH) {
                preimage = bytes.concat(
                    preimageStart,
                    bytes.concat(_transaction.inputs[i].txId).convertEndian(),
                    bytes.concat(_transaction.inputs[i].vout).convertEndian(),
                    // scriptcode
                    bytes3(0x1976a9),
                    scriptPubKey.readFromMemory(1, 21),
                    bytes2(0x88ac)
                );
                // avoiding `stack too deep` error
                preimage = bytes.concat(
                    preimage,
                    bytes.concat(
                        _transactions[_transaction.inputs[i].txId].outputs[uint32(_transaction.inputs[i].vout)].amount
                    ).convertEndian(),
                    bytes.concat(_transaction.inputs[i].sequence).convertEndian(),
                    preimageEnd
                );
                _execute(scriptPubKey, preimage, _transaction.witness[i]);
            } else if (scriptType == ScriptType.P2WSH) {
                preimage = bytes.concat(
                    preimageStart,
                    bytes.concat(_transaction.inputs[i].txId).convertEndian(),
                    bytes.concat(_transaction.inputs[i].vout).convertEndian()
                );
                // avoiding `stack too deep` error
                uint256 len = _transaction.witness[i][_transaction.witness[i].length - 1].length;
                preimage = bytes.concat(preimage, len.toVarint());
                len = _transaction.witness[i].length - 1;
                preimage = bytes.concat(preimage, _transaction.witness[i][len]);
                preimage = bytes.concat(
                    preimage,
                    bytes.concat(
                        _transactions[_transaction.inputs[i].txId].outputs[uint32(_transaction.inputs[i].vout)].amount
                    ).convertEndian(),
                    bytes.concat(_transaction.inputs[i].sequence).convertEndian(),
                    preimageEnd
                );
                _execute(scriptPubKey, preimage, _transaction.witness[i]);
            }
            tempTx.inputs[i].scriptSig = "";
        }
    }

    /**
     * Gets the script type
     * @param _scriptPubKey - ScriptPubKey
     * @return ScriptType - Script type
     * @dev Reverts if the script type is not supported
     */
    function _getScriptType(bytes memory _scriptPubKey) internal pure returns (ScriptType) {
        if (
            (_scriptPubKey.length == 67 && _scriptPubKey[0] == 0x41 && _scriptPubKey[66] == 0xac)
                || (_scriptPubKey.length == 35 && _scriptPubKey[0] == 0x21 && _scriptPubKey[34] == 0xac)
        ) {
            return ScriptType.P2PK;
        } else if (
            _scriptPubKey.length == 25 && _scriptPubKey[0] == 0x76 && _scriptPubKey[1] == 0xa9
                && _scriptPubKey[2] == 0x14 && _scriptPubKey[23] == 0x88 && _scriptPubKey[24] == 0xac
        ) {
            return ScriptType.P2PKH;
        } else if (
            _scriptPubKey.length == 23 && _scriptPubKey[0] == 0xa9 && _scriptPubKey[1] == 0x14
                && _scriptPubKey[22] == 0x87
        ) {
            return ScriptType.P2SH;
        } else if (_scriptPubKey.length == 22 && _scriptPubKey[0] == 0x00 && _scriptPubKey[1] == 0x14) {
            return ScriptType.P2WPKH;
        } else if (_scriptPubKey.length == 34 && _scriptPubKey[0] == 0x00 && _scriptPubKey[1] == 0x20) {
            return ScriptType.P2WSH;
        } else {
            revert NotSupported();
        }
    }

    /**
     * Executes the script
     * @param _script - Script
     * @param _preimage - Preimage to hash
     * @param _witness - Witness
     */
    function _execute(bytes memory _script, bytes memory _preimage, bytes[] memory _witness) internal {
        script.execute(
            bytes.concat(_script.length.toVarint(), _script), bytes.concat(_preimage, SIGHASH_ALL).hash256(), _witness
        );
    }

    /**
     * Calculates the target
     * @param _bits - Bits
     * @return target - Target
     */
    function _getTarget(uint256 _bits) internal pure returns (uint256 target) {
        uint256 exponent = _bits >> 24;
        uint256 coefficient = _bits & 0xffffff;
        target = coefficient * 256 ** (exponent - 3);
    }

    /**
     * Calculates the new bits of the block every 2016 blocks,
     * otherwise returns 0
     * @param _height - Height of the block
     * @return newBits - New bits
     */
    function _getNewBits(uint256 _height) internal view returns (bytes4 newBits) {
        if (_height == 0) return DEFAULT_BITS;
        else if (_height % 2016 != 0) return _blocks[_height - 1].bits;
        uint256 temp1 = _height - 2016;
        // time difference
        uint256 temp2 = uint32(_blocks[_height - 1].timestamp) - uint32(_blocks[temp1].timestamp);
        if (temp2 > MAX_TIME) temp2 = MAX_TIME;
        else if (temp2 < MIN_TIME) temp2 = MIN_TIME;

        // previous target
        uint256 temp3 = _getTarget(uint32(_blocks[temp1].bits));
        // new target
        temp1 = temp3 * temp2 / 2 weeks;
        if (temp1 > DEFAULT_TARGET) return DEFAULT_BITS;

        uint256 countZeroes;
        // mask
        temp2 = 1 << 255;
        while (temp1 & temp2 == 0) {
            ++countZeroes;
            temp2 >>= 1;
        }
        countZeroes /= 8;

        bytes memory target = bytes.concat(bytes32(temp1));
        if (target[countZeroes] > 0x7f) {
            // exponent
            temp2 = 33 - countZeroes;
            // coefficient
            temp3 = uint16(bytes2(target.readFromMemory(countZeroes, 2)));
        } else {
            // exponent
            temp2 = 32 - countZeroes;
            // coefficient
            temp3 = uint24(bytes3(target.readFromMemory(countZeroes, 3)));
        }

        newBits = bytes4(uint32(temp3 + (temp2 << 24)));
    }

    /**
     * Recursively calculates the merkle root
     * @dev _transactionHashes.length is at least 1 (coinbase tx)
     * @param _transactionHashes - Transaction hashes
     * @return Merkle root
     */
    function _getMerkleRoot(bytes32[] memory _transactionHashes) internal pure returns (bytes32) {
        uint256 len = _transactionHashes.length;
        if (len == 1) return _transactionHashes[0];

        bytes32[] memory temp = new bytes32[](len % 2 == 0 ? len / 2 : len / 2 + 1);
        for (uint256 i; i < len; i += 2) {
            if (i + 1 < len) {
                temp[i / 2] = bytes32(bytes.concat(_transactionHashes[i], _transactionHashes[i + 1]).hash256());
            } else {
                temp[i / 2] = bytes32(bytes.concat(_transactionHashes[i], _transactionHashes[i]).hash256());
            }
        }
        return _getMerkleRoot(temp);
    }

    /**
     * Calculates the nonce
     * @dev Assumes that uint32 is enough to find a nonce,
     * in real Bitcoin miners also change timestamp and coinbase tx.
     * Additionally, this may run out of gas
     * @param _block - Block
     */
    function _findNonce(Block memory _block) internal pure {
        uint256 target = _getTarget(uint32(_block.bits));
        bytes32 blockHash = _block.serializeBlockHeader().hash256().convertEndian();
        while (uint256(blockHash) > target) {
            _block.nonce = bytes4(uint32(_block.nonce) + 1);
            blockHash = _block.serializeBlockHeader().hash256().convertEndian();
        }
    }
}
