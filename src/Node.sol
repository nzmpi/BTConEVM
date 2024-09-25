// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "./Script.sol";
import {SerialLib} from "./lib/SerialLib.sol";
import {Transaction} from "./lib/Structs.sol";
import {ScriptType} from "./lib/Types.sol";
import "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

contract Node {
    using SerialLib for Transaction;
    using Utils for bytes;
    using Varint for uint256;

    bytes4 constant SIGHASH_ALL = hex"01000000";
    Script immutable script;
    mapping(bytes32 txId => mapping(bytes4 vout => bool unspent)) public UTXOs;
    mapping(bytes32 txId => Transaction) transactions;
    mapping(uint256 blockId => Transaction[]) public blocks;

    error InvalidFee();
    error InvalidTxInputs();
    error NotSupported();
    error UTXOisSpent();

    constructor(Script _script) {
        script = _script;
    }

    function validate(Transaction calldata transaction, bytes[] calldata data) external {
        uint256 len = transaction.inputs.length;
        if (len == 0 || len != data.length) revert InvalidTxInputs();
        bytes32 txId;
        bytes4 vout;
        uint256 inputSum;
        for (uint256 i; i < len; ++i) {
            txId = transaction.inputs[i].txId;
            vout = transaction.inputs[i].vout;
            if (!UTXOs[txId][vout]) revert UTXOisSpent();
            delete UTXOs[txId][vout];
            inputSum += uint64(transactions[txId].outputs[uint32(vout)].amount);
        }
        _verifySignature(transaction, len, data);
        len = transaction.outputs.length;
        uint256 outputSum;
        for (uint256 i; i < len; ++i) {
            outputSum += uint64(transaction.outputs[i].amount);
        }

        if (outputSum > inputSum) revert InvalidFee();
    }

    function getTransaction(bytes32 _txId) external view returns (Transaction memory) {
        return transactions[_txId];
    }

    function _verifySignature(Transaction calldata _transaction, uint256 _len, bytes[] calldata _data) internal {
        Transaction memory tempTx = _transaction;
        for (uint256 i; i < _len; ++i) {
            tempTx.inputs[i].scriptSig = hex"";
        }
        bytes32 signatureHash;
        bytes memory scriptPubKey;
        ScriptType scriptType;
        for (uint256 i; i < _len; ++i) {
            scriptPubKey =
                transactions[_transaction.inputs[i].txId].outputs[uint32(_transaction.inputs[i].vout)].scriptPubKey;
            scriptType = _getScriptType(scriptPubKey);
            if (scriptType == ScriptType.P2PKH) {
                tempTx.inputs[i].scriptSig = scriptPubKey;
                signatureHash = bytes.concat(tempTx.serializeTransaction(), SIGHASH_ALL).hash256();
                script.execute(
                    bytes.concat(
                        (_transaction.inputs[i].scriptSig.length + scriptPubKey.length).toVarint(),
                        _transaction.inputs[i].scriptSig,
                        scriptPubKey
                    ),
                    signatureHash
                );
            } else if (scriptType == ScriptType.P2SH) {
                tempTx.inputs[i].scriptSig = _data[i];
                signatureHash = bytes.concat(tempTx.serializeTransaction(), SIGHASH_ALL).hash256();
                script.execute(
                    bytes.concat(
                        (_transaction.inputs[i].scriptSig.length + scriptPubKey.length).toVarint(),
                        _transaction.inputs[i].scriptSig,
                        scriptPubKey
                    ),
                    signatureHash
                );
            }
            tempTx.inputs[i].scriptSig = hex"";
        }
    }

    function _getScriptType(bytes memory _scriptPubKey) internal pure returns (ScriptType) {
        if (
            _scriptPubKey.length == 25 && _scriptPubKey[0] == 0x76 && _scriptPubKey[1] == 0xa9
                && _scriptPubKey[2] == 0x14 && _scriptPubKey[23] == 0x88 && _scriptPubKey[24] == 0xac
        ) {
            return ScriptType.P2PKH;
        } else if (
            _scriptPubKey.length == 23 && _scriptPubKey[0] == 0xa9 && _scriptPubKey[1] == 0x14
                && _scriptPubKey[22] == 0x87
        ) {
            return ScriptType.P2SH;
        } else {
            revert NotSupported();
        }
    }
}
