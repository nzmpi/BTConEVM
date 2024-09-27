// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Address} from "./lib/Address.sol";
import {ECBTC} from "./lib/ECBTC.sol";
import {Node} from "./Node.sol";
import {SerialLib} from "./lib/SerialLib.sol";
import {SigLib} from "./lib/SigLib.sol";
import "./lib/Structs.sol";
import {ScriptType} from "./lib/Types.sol";
import {Utils} from "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

/**
 * @title Wallet
 * @notice A wallet for signing and sending transactions
 * @dev Only supports P2PKH and P2SH scripts
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
        bool[] areCompressed;
    }

    struct OutputArgs {
        ScriptType[] outputTypes;
        bytes8[] amounts;
        bytes[] tos; // for P2PKH
        bytes[] redeemScripts; // for P2SH
    }

    struct PublicKey {
        Point publicKeyPoint;
        bytes publicKeyCompressed;
        bytes publicKeyUncompressed;
    }

    bytes4 constant VERSION = 0x00000001;
    bytes4 constant SEQUENCE = 0xffffffff;
    bytes4 constant SIGHASH_ALL = 0x01000000;
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
            publicKeys[i] = PublicKey({
                publicKeyPoint: publicKey_,
                publicKeyCompressed: publicKeyCompressed,
                publicKeyUncompressed: publicKey_.serializePublicKey(false)
            });
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
            version: VERSION,
            inputs: _getTxInputs(inputArgs.txIds, inputArgs.vouts),
            outputs: _getTxOutputs(outputArgs),
            locktime: 0
        });

        (bytes[] memory scriptSigs, bytes[] memory redeemScripts) = _getScriptSigsAndRedeemScripts(
            node, inputArgs.inputTypes, inputArgs.signingPrivateKeys, transaction, inputArgs.areCompressed
        );

        uint256 len = inputArgs.inputTypes.length;
        for (uint256 i; i < len; ++i) {
            transaction.inputs[i].scriptSig = scriptSigs[i];
        }
        txId = transaction.serializeTransaction().hash256().convertEndian();
        node.validate(transaction, redeemScripts);
    }

    /**
     * Returns a P2PKH address
     * @param index - Index of the private key
     * @param isCompressed - Compressed or uncompressed
     * @param isMainnet - Mainnet or testnet
     * @return address - Address
     */
    function getP2PKHAddress(uint256 index, bool isCompressed, bool isMainnet) external view returns (string memory) {
        return isCompressed
            ? string(publicKeys[index].publicKeyCompressed.hash160().getAddress(isMainnet, ScriptType.P2PKH))
            : string(publicKeys[index].publicKeyUncompressed.hash160().getAddress(isMainnet, ScriptType.P2PKH));
    }

    /**
     * Returns a P2SH address
     * @param m - Amount of private keys to sign to make m-of-n multisig, where n = privateKeys.length
     * @param isMainnet - Mainnet or testnet
     * @return address - Address
     */
    function getP2SHAddress(uint256 m, bool isMainnet) external view returns (string memory) {
        if (m == 0 || m > privateKeys.length) revert WrongAmountOfKeys(m);
        return string(
            bytes.concat(m.getNumberForScript(), redeemScriptBase).hash160().getAddress(isMainnet, ScriptType.P2SH)
        );
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
            txInputs[i] = TxInput({txId: _txIds[i], vout: _vouts[i], scriptSig: hex"", sequence: SEQUENCE});
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
                || len != _outputArgs.redeemScripts.length
        ) revert WrongOutputData();
        txOutputs = new TxOutput[](len);
        for (uint256 i; i < len; ++i) {
            if (_outputArgs.outputTypes[i] == ScriptType.P2PKH) {
                txOutputs[i] = TxOutput({amount: _outputArgs.amounts[i], scriptPubKey: _p2pkh(_outputArgs.tos[i])});
            } else if (_outputArgs.outputTypes[i] == ScriptType.P2SH) {
                txOutputs[i] =
                    TxOutput({amount: _outputArgs.amounts[i], scriptPubKey: _p2sh(_outputArgs.redeemScripts[i])});
            } else {
                revert NotSupported(_outputArgs.outputTypes[i]);
            }
        }
    }

    /**
     * Returns scriptSigs and redeem scripts
     * @param _node - Node to call
     * @param _inputTypes - Input types
     * @param _signingPrivateKeys - Signing private keys
     * @param _transaction - Transaction to send
     * @param _areCompressed - Whether the public keys are compressed or not
     * @return scriptSigs - scriptSigs
     * @return redeemScripts - Redeem scripts
     */
    function _getScriptSigsAndRedeemScripts(
        Node _node,
        ScriptType[] calldata _inputTypes,
        uint256[][] calldata _signingPrivateKeys,
        Transaction memory _transaction,
        bool[] calldata _areCompressed
    ) internal view returns (bytes[] memory scriptSigs, bytes[] memory redeemScripts) {
        uint256 len = _transaction.inputs.length;
        if (len == 0 || len != _inputTypes.length || len != _signingPrivateKeys.length || len != _areCompressed.length)
        {
            revert WrongInputData();
        }
        bytes memory temp;
        bytes memory signature;
        bytes32 signatureHash;
        scriptSigs = new bytes[](len);
        redeemScripts = new bytes[](len);
        for (uint256 i; i < len; ++i) {
            if (_inputTypes[i] == ScriptType.P2PKH) {
                _transaction.inputs[i].scriptSig = _node.getTransaction(_transaction.inputs[i].txId).outputs[uint32(
                    _transaction.inputs[i].vout
                )].scriptPubKey;
                signatureHash = bytes.concat(_transaction.serializeTransaction(), SIGHASH_ALL).hash256();
                temp = _getSignature(signatureHash, _signingPrivateKeys[i][0]);
                scriptSigs[i] = _getScriptSigForP2PKH(
                    temp,
                    _areCompressed[i]
                        ? publicKeys[_signingPrivateKeys[i][0]].publicKeyCompressed
                        : publicKeys[_signingPrivateKeys[i][0]].publicKeyUncompressed
                );
            } else if (_inputTypes[i] == ScriptType.P2SH) {
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
            } else {
                revert NotSupported(_inputTypes[i]);
            }

            _transaction.inputs[i].scriptSig = hex"";
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
     * Returns scriptPubKey for P2PKH
     * @param _address - Address of the receiver
     * @return scriptPubKey - ScriptPubKey
     */
    function _p2pkh(bytes memory _address) internal pure returns (bytes memory) {
        return bytes.concat(
            bytes1(0x76), bytes1(0xa9), bytes1(0x14), _address.getHashFromAddress(), bytes1(0x88), bytes1(0xac)
        );
    }

    /**
     * Returns scriptPubKey for P2SH
     * @param _redeemScript - Redeem script
     * @return scriptPubKey - ScriptPubKey
     */
    function _p2sh(bytes memory _redeemScript) internal pure returns (bytes memory) {
        return bytes.concat(bytes1(0xa9), bytes1(0x14), _redeemScript.hash160(), bytes1(0x87));
    }
}
