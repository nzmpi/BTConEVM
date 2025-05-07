// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Node} from "./Node.sol";
import {Address} from "./lib/Address.sol";
import {ECBTC} from "./lib/ECBTC.sol";
import {SerialLib} from "./lib/SerialLib.sol";
import {SigLib} from "./lib/SigLib.sol";
import "./lib/Structs.sol";
import {ScriptType} from "./lib/Types.sol";
import {Utils} from "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

/**
 * @title Wallet
 * @notice A "wallet" for signing and sending transactions
 * @dev Supports P2PKH, P2SH, P2WPKH and P2WSH scripts
 * @author https://github.com/nzmpi
 */
contract Wallet {
    using Address for *;
    using ECBTC for uint256;
    using SerialLib for *;
    using SigLib for uint256;
    using Utils for *;
    using Varint for uint256;

    struct InputArgs {
        ScriptType[] inputTypes;
        uint256[][] signingPrivateKeys;
        bytes32[] txIds;
        bytes4[] vouts;
    }

    struct OutputArgs {
        ScriptType[] outputTypes;
        bytes8[] amounts;
        bytes[] tos; // for P2PKH and P2WPKH
        bytes[] scripts; // redeem scripts for P2SH and witness scripts for P2WSH
    }

    struct PublicKey {
        Point publicKeyPoint;
        bytes publicKeyCompressed;
    }

    bytes4 constant VERSION = 0x00000001;
    bytes4 constant SEQUENCE = 0xffffffff;
    bytes4 constant SIGHASH_ALL = 0x01000000;
    // DO NOT USE YOUR REAL PRIVATE KEYS!
    uint256[] privateKeys;
    mapping(uint256 => PublicKey) publicKeys;
    bytes redeemScriptBase;

    error WrongAmountOfKeys(uint256 m);
    error WrongInputData();
    error WrongOutputData();
    error NotSupported(ScriptType _type);

    constructor(uint256[] memory _privateKeys) payable {
        uint256 n = _privateKeys.length;
        if (n == 0) revert WrongAmountOfKeys(n);
        privateKeys = _privateKeys;
        Point memory publicKey_;
        bytes memory publicKeyCompressed;
        bytes memory redeemScript;
        for (uint256 i; i < n; ++i) {
            publicKey_ = _privateKeys[i].mulG();
            publicKeyCompressed = publicKey_.serializePublicKey(true);
            publicKeys[i] = PublicKey({publicKeyPoint: publicKey_, publicKeyCompressed: publicKeyCompressed});
            redeemScript =
                bytes.concat(redeemScript, publicKeyCompressed.length.getLengthForScript(), publicKeyCompressed);
        }
        redeemScriptBase = bytes.concat(redeemScript, n.getNumberForScript(), bytes1(0xae));
    }

    /**
     * Sends a transaction
     * @param node - Node to call
     * @param inputArgs - Input arguments
     * @param outputArgs - Output arguments
     * @return txId - Transaction ID
     */
    function sendTransaction(Node node, InputArgs calldata inputArgs, OutputArgs calldata outputArgs)
        external
        returns (bytes32 txId)
    {
        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: VERSION,
            inputs: _getTxInputs(inputArgs.txIds, inputArgs.vouts),
            outputs: _getTxOutputs(outputArgs),
            locktime: 0,
            witness: new bytes[][](0)
        });

        (bool isSegwit, bytes[] memory scriptSigs, bytes[] memory redeemScripts, bytes[][] memory witnesses) =
            _signTransaction(node, inputArgs.inputTypes, inputArgs.signingPrivateKeys, transaction);

        uint256 len = inputArgs.inputTypes.length;
        for (uint256 i; i < len; ++i) {
            transaction.inputs[i].scriptSig = scriptSigs[i];
        }

        if (isSegwit) {
            transaction.isSegwit = isSegwit;
            transaction.witness = witnesses;
        }

        txId = transaction.serializeTransactionLegacy().hash256().convertEndian();
        node.validate(transaction, redeemScripts);
    }

    /**
     * Returns an address based on the script type
     * @param scriptType - Script type
     * @param m - Index of the private key or amount of private keys to sign to make m-of-n multisig, where n == privateKeys.length
     * @param isMainnet - Mainnet or testnet
     * @return res - Address
     */
    function getAddress(ScriptType scriptType, uint256 m, bool isMainnet) external view returns (string memory res) {
        bytes memory hash;
        if (scriptType == ScriptType.P2PKH || scriptType == ScriptType.P2WPKH) {
            hash = bytes.concat(publicKeys[m].publicKeyCompressed.hash160());
        } else if (scriptType == ScriptType.P2SH) {
            if (m == 0 || m > privateKeys.length) revert WrongAmountOfKeys(m);
            hash = bytes.concat(bytes.concat(m.getNumberForScript(), redeemScriptBase).hash160());
        } else if (scriptType == ScriptType.P2WSH) {
            if (m == 0 || m > privateKeys.length) revert WrongAmountOfKeys(m);
            hash = bytes.concat(sha256(bytes.concat(m.getNumberForScript(), redeemScriptBase)));
        }

        res = string(hash.getAddress(isMainnet, scriptType));
    }

    /**
     * Returns transaction inputs
     * @param _txIds - Transaction IDs
     * @param _vouts - Vouts
     * @return txInputs - Transaction inputs without scriptSigs
     */
    function _getTxInputs(bytes32[] calldata _txIds, bytes4[] calldata _vouts)
        internal
        pure
        returns (TxInput[] memory txInputs)
    {
        uint256 len = _txIds.length;
        if (len == 0 || len != _vouts.length) revert WrongInputData();
        txInputs = new TxInput[](len);
        for (uint256 i; i < len; ++i) {
            txInputs[i] = TxInput({txId: _txIds[i], vout: _vouts[i], scriptSig: "", sequence: SEQUENCE});
        }
    }

    /**
     * Returns transaction outputs
     * @param _outputArgs - Output arguments
     * @return txOutputs - Transaction outputs
     */
    function _getTxOutputs(OutputArgs calldata _outputArgs) internal pure returns (TxOutput[] memory txOutputs) {
        uint256 len = _outputArgs.outputTypes.length;
        if (
            len == 0 || len != _outputArgs.amounts.length || len != _outputArgs.tos.length
                || len != _outputArgs.scripts.length
        ) revert WrongOutputData();

        txOutputs = new TxOutput[](len);
        for (uint256 i; i < len; ++i) {
            if (_outputArgs.outputTypes[i] == ScriptType.P2PKH) {
                txOutputs[i] = TxOutput({
                    amount: _outputArgs.amounts[i],
                    scriptPubKey: _getScriptPubKey(ScriptType.P2PKH, _outputArgs.tos[i])
                });
            } else if (_outputArgs.outputTypes[i] == ScriptType.P2SH) {
                txOutputs[i] = TxOutput({
                    amount: _outputArgs.amounts[i],
                    scriptPubKey: _getScriptPubKey(ScriptType.P2SH, _outputArgs.scripts[i])
                });
            } else if (_outputArgs.outputTypes[i] == ScriptType.P2WPKH) {
                txOutputs[i] = TxOutput({
                    amount: _outputArgs.amounts[i],
                    scriptPubKey: _getScriptPubKey(ScriptType.P2WPKH, _outputArgs.tos[i])
                });
            } else if (_outputArgs.outputTypes[i] == ScriptType.P2WSH) {
                txOutputs[i] = TxOutput({
                    amount: _outputArgs.amounts[i],
                    scriptPubKey: _getScriptPubKey(ScriptType.P2WSH, _outputArgs.scripts[i])
                });
            } else {
                revert NotSupported(_outputArgs.outputTypes[i]);
            }
        }
    }

    /**
     * Returns scriptSigs and redeem scripts
     * @param _node - Node to call
     * @param _inputTypes - Input types
     * @param _signingPrivateKeys - Indices of the signing private keys
     * @param _transaction - Transaction to send
     * @return isSegwit - Whether the transaction is segwit
     * @return scriptSigs - scriptSigs
     * @return redeemScripts - Redeem scripts
     * @return witnesses - Witnesses
     */
    function _signTransaction(
        Node _node,
        ScriptType[] calldata _inputTypes,
        uint256[][] calldata _signingPrivateKeys,
        Transaction memory _transaction
    )
        internal
        view
        returns (bool isSegwit, bytes[] memory scriptSigs, bytes[] memory redeemScripts, bytes[][] memory witnesses)
    {
        uint256 len = _transaction.inputs.length;
        if (len == 0 || len != _inputTypes.length || len != _signingPrivateKeys.length) {
            revert WrongInputData();
        }
        bytes memory temp;
        bytes32 signatureHash;
        scriptSigs = new bytes[](len);
        redeemScripts = new bytes[](len);
        witnesses = new bytes[][](len);
        for (uint256 i; i < len; ++i) {
            if (_inputTypes[i] == ScriptType.P2PKH) {
                _transaction.inputs[i].scriptSig = _node.getTransaction(_transaction.inputs[i].txId).outputs[uint32(
                    _transaction.inputs[i].vout
                )].scriptPubKey;
                signatureHash = bytes.concat(_transaction.serializeTransaction(), SIGHASH_ALL).hash256();
                temp = _getSignature(signatureHash, _signingPrivateKeys[i][0]);
                scriptSigs[i] = _getScriptSigForP2PKH(temp, publicKeys[_signingPrivateKeys[i][0]].publicKeyCompressed);
            } else if (_inputTypes[i] == ScriptType.P2SH) {
                bytes memory signature;
                // op_0
                temp = hex"00";
                uint256 m = _signingPrivateKeys[i].length;
                redeemScripts[i] = bytes.concat(m.getNumberForScript(), redeemScriptBase);
                _transaction.inputs[i].scriptSig = redeemScripts[i];
                signatureHash = bytes.concat(_transaction.serializeTransaction(), SIGHASH_ALL).hash256();
                for (uint256 j; j < m; ++j) {
                    signature = _getSignature(signatureHash, _signingPrivateKeys[i][j]);
                    temp = bytes.concat(temp, signature.length.getLengthForScript(), signature);
                }
                scriptSigs[i] = bytes.concat(temp, redeemScripts[i].length.getLengthForScript(), redeemScripts[i]);
            } else if (_inputTypes[i] == ScriptType.P2WPKH) {
                isSegwit = true;
                bytes8 amount = _node.getTransaction(_transaction.inputs[i].txId).outputs[uint32(
                    _transaction.inputs[i].vout
                )].amount;
                witnesses[i] = _getWitnessForP2WPKH(_transaction, i, amount, _signingPrivateKeys[i][0]);
            } else if (_inputTypes[i] == ScriptType.P2WSH) {
                isSegwit = true;
                bytes8 amount = _node.getTransaction(_transaction.inputs[i].txId).outputs[uint32(
                    _transaction.inputs[i].vout
                )].amount;
                witnesses[i] = _getWitnessForP2WSH(_transaction, i, amount, _signingPrivateKeys[i]);
            } else {
                revert NotSupported(_inputTypes[i]);
            }

            _transaction.inputs[i].scriptSig = "";
        }
    }

    /**
     * Returns signature
     * @param _signatureHash - Digest to sign
     * @param _privateKeyIndex - Index of the private key to sign with
     * @return signature - Signature
     */
    function _getSignature(bytes32 _signatureHash, uint256 _privateKeyIndex)
        internal
        view
        returns (bytes memory signature)
    {
        signature = bytes.concat(
            uint256(_signatureHash).sign(privateKeys[_privateKeyIndex]).serializeSignature(), bytes1(SIGHASH_ALL)
        );
    }

    /**
     * Returns scriptSig for P2PKH
     * @param _signature - Signature
     * @param _publicKey - Public key
     * @return scriptSig - ScriptSig
     */
    function _getScriptSigForP2PKH(bytes memory _signature, bytes memory _publicKey)
        internal
        pure
        returns (bytes memory scriptSig)
    {
        scriptSig = bytes.concat(
            _signature.length.getLengthForScript(), _signature, _publicKey.length.getLengthForScript(), _publicKey
        );
    }

    /**
     * Returns witness for P2WPKH
     * @param _transaction - Transaction
     * @param _inputIndex - Index of the input
     * @param _amount - Amount from the output corresponding to the input
     * @param _privateKeyIndex - Private key index to sign with
     * @return witness - Witness
     */
    function _getWitnessForP2WPKH(
        Transaction memory _transaction,
        uint256 _inputIndex,
        bytes8 _amount,
        uint256 _privateKeyIndex
    ) internal view returns (bytes[] memory witness) {
        uint256 len = _transaction.inputs.length;
        bytes memory temp;
        bytes memory anotherTemp;
        for (uint256 i; i < len; ++i) {
            // prevouts
            temp = bytes.concat(
                temp,
                bytes.concat(_transaction.inputs[i].txId).convertEndian(),
                bytes.concat(_transaction.inputs[i].vout).convertEndian()
            );
            // sequences
            anotherTemp = bytes.concat(anotherTemp, bytes.concat(_transaction.inputs[i].sequence).convertEndian());
        }
        temp = bytes.concat(
            bytes.concat(_transaction.version).convertEndian(),
            temp.hash256(),
            anotherTemp.hash256(),
            bytes.concat(_transaction.inputs[_inputIndex].txId).convertEndian(),
            bytes.concat(_transaction.inputs[_inputIndex].vout).convertEndian()
        );
        // avoiding `stack too deep` error
        temp = bytes.concat(
            temp,
            // scriptcode
            bytes4(0x1976a914),
            publicKeys[_privateKeyIndex].publicKeyCompressed.hash160(),
            bytes2(0x88ac),
            bytes.concat(_amount).convertEndian(),
            bytes.concat(_transaction.inputs[_inputIndex].sequence).convertEndian()
        );

        len = _transaction.outputs.length;
        anotherTemp = "";
        for (uint256 i; i < len; ++i) {
            anotherTemp = bytes.concat(
                anotherTemp,
                bytes.concat(_transaction.outputs[i].amount).convertEndian(),
                _transaction.outputs[i].scriptPubKey.length.toVarint(),
                _transaction.outputs[i].scriptPubKey
            );
        }
        temp = bytes.concat(temp, anotherTemp.hash256(), bytes.concat(_transaction.locktime).convertEndian());
        bytes32 signatureHash = bytes.concat(temp, SIGHASH_ALL).hash256();

        witness = new bytes[](2);
        witness[0] = _getSignature(signatureHash, _privateKeyIndex);
        witness[1] = publicKeys[_privateKeyIndex].publicKeyCompressed;
    }

    /**
     * Returns witness for P2WSH
     * @param _transaction - Transaction
     * @param _inputIndex - Index of the input
     * @param _amount - Amount from the output corresponding to the input
     * @param _privateKeys - Indices of the private keys to sign with
     * @return witness - Witness
     */
    function _getWitnessForP2WSH(
        Transaction memory _transaction,
        uint256 _inputIndex,
        bytes8 _amount,
        uint256[] memory _privateKeys
    ) internal view returns (bytes[] memory witness) {
        uint256 len = _transaction.inputs.length;
        bytes memory temp;
        bytes memory anotherTemp;
        for (uint256 i; i < len; ++i) {
            // prevouts
            temp = bytes.concat(
                temp,
                bytes.concat(_transaction.inputs[i].txId).convertEndian(),
                bytes.concat(_transaction.inputs[i].vout).convertEndian()
            );
            // sequences
            anotherTemp = bytes.concat(anotherTemp, bytes.concat(_transaction.inputs[i].sequence).convertEndian());
        }
        temp = bytes.concat(
            bytes.concat(_transaction.version).convertEndian(),
            temp.hash256(),
            anotherTemp.hash256(),
            bytes.concat(_transaction.inputs[_inputIndex].txId).convertEndian(),
            bytes.concat(_transaction.inputs[_inputIndex].vout).convertEndian()
        );

        uint256 m = _privateKeys.length + 1;
        // op_0, m signatures and witnessScript
        witness = new bytes[](m + 1);
        witness[m] = bytes.concat((m - 1).getNumberForScript(), redeemScriptBase);
        // avoiding `stack too deep` error
        temp = bytes.concat(
            temp,
            // scriptcode
            witness[m].length.toVarint(),
            witness[m],
            bytes.concat(_amount).convertEndian(),
            bytes.concat(_transaction.inputs[_inputIndex].sequence).convertEndian()
        );

        len = _transaction.outputs.length;
        anotherTemp = "";
        for (uint256 i; i < len; ++i) {
            anotherTemp = bytes.concat(
                anotherTemp,
                bytes.concat(_transaction.outputs[i].amount).convertEndian(),
                _transaction.outputs[i].scriptPubKey.length.toVarint(),
                _transaction.outputs[i].scriptPubKey
            );
        }
        temp = bytes.concat(temp, anotherTemp.hash256(), bytes.concat(_transaction.locktime).convertEndian());

        bytes32 signatureHash = bytes.concat(temp, SIGHASH_ALL).hash256();
        --m;
        for (uint256 i; i < m; ++i) {
            witness[i + 1] = _getSignature(signatureHash, _privateKeys[i]);
        }
    }

    /**
     * Returns scriptPubKey
     * @param _type - Script type
     * @param _data - Address of the receiver or redeem/witness script
     * @return scriptPubKey
     */
    function _getScriptPubKey(ScriptType _type, bytes memory _data) internal pure returns (bytes memory) {
        if (_type == ScriptType.P2PKH) {
            return bytes.concat(
                bytes1(0x76), bytes1(0xa9), bytes1(0x14), _data.getHashFromAddress(), bytes1(0x88), bytes1(0xac)
            );
        } else if (_type == ScriptType.P2SH) {
            return bytes.concat(bytes1(0xa9), bytes1(0x14), _data.hash160(), bytes1(0x87));
        } else if (_type == ScriptType.P2WPKH) {
            return bytes.concat(bytes1(0x00), bytes1(0x14), _data.getHashFromAddress());
        } else if (_type == ScriptType.P2WSH) {
            return bytes.concat(bytes1(0x00), bytes1(0x20), sha256(_data));
        } else {
            revert NotSupported(_type);
        }
    }
}
