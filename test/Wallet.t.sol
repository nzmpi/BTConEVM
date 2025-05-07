// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Wallet} from "../src/Wallet.sol";
import {Address} from "../src/lib/Address.sol";
import "../src/lib/Structs.sol";
import {ScriptType} from "../src/lib/Types.sol";
import "../src/lib/Utils.sol";
import {MockNode} from "./Node.t.sol";
import "./utils/BaseTest.sol";

contract MockWallet is Wallet {
    using Utils for uint256;

    constructor(uint256[] memory _privateKeys) Wallet(_privateKeys) {}

    function getRedeemScript(uint256 m) external view returns (bytes memory) {
        return bytes.concat(m.getNumberForScript(), redeemScriptBase);
    }
}

contract TestWallet is BaseTest {
    using Address for bytes;
    using Utils for bytes;

    MockNode node;
    MockWallet mock;

    function setUp() public {
        uint256[] memory pks = new uint256[](3);
        pks[0] = privateKey;
        pks[1] = anotherPrivateKey;
        pks[2] = thirdPrivateKey;
        mock = new MockWallet(pks);
        node = new MockNode();
    }

    function test_sendTransaction() public {
        Wallet.InputArgs memory inputs = _getInputs();
        Wallet.OutputArgs memory outputs = _getOutputs();

        _addTransaction(
            false,
            inputs.txIds[0],
            inputs.vouts[0],
            bytes.concat(
                bytes3(0x76a914), bytes(mock.getAddress(ScriptType.P2PKH, 0, true)).getHashFromAddress(), bytes2(0x88ac)
            )
        );
        _addTransaction(
            false,
            inputs.txIds[1],
            inputs.vouts[1],
            bytes.concat(bytes2(0xa914), mock.getRedeemScript(3).hash160(), bytes1(0x87))
        );
        _addTransaction(
            true,
            inputs.txIds[2],
            inputs.vouts[2],
            bytes.concat(bytes2(0x0014), bytes(mock.getAddress(ScriptType.P2WPKH, 0, true)).getHashFromAddress())
        );
        _addTransaction(
            true, inputs.txIds[3], inputs.vouts[3], bytes.concat(bytes2(0x0020), sha256(mock.getRedeemScript(3)))
        );
        bytes32 txId = mock.sendTransaction(node, inputs, outputs);
        assertEq(node.collectedFees(), 3000);

        // should be able to use the previous output
        inputs.inputTypes = new ScriptType[](1);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.signingPrivateKeys = new uint256[][](1);
        inputs.signingPrivateKeys[0] = new uint256[](1);
        inputs.signingPrivateKeys[0][0] = 1;
        inputs.txIds = new bytes32[](1);
        inputs.txIds[0] = txId;
        inputs.vouts = new bytes4[](1);

        outputs.outputTypes = new ScriptType[](1);
        outputs.outputTypes[0] = ScriptType.P2PKH;
        outputs.amounts = new bytes8[](1);
        outputs.amounts[0] = bytes8(uint64(10));
        outputs.tos = new bytes[](1);
        outputs.tos[0] = bytes("1E1acnMGhWR69vSgH8c4CGEQHVpaVdQdbH");
        outputs.scripts = new bytes[](1);

        mock.sendTransaction(node, inputs, outputs);
        assertEq(node.collectedFees(), 3090);
    }

    function test_invalid_sendTransaction() public {
        Wallet.InputArgs memory inputs;
        Wallet.OutputArgs memory outputs;

        vm.expectRevert(Wallet.WrongInputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        inputs.txIds = new bytes32[](1);
        inputs.txIds[0] = keccak256("id1");
        inputs.vouts = new bytes4[](0);
        vm.expectRevert(Wallet.WrongInputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        inputs.vouts = new bytes4[](1);
        vm.expectRevert(Wallet.WrongOutputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        outputs.outputTypes = new ScriptType[](1);
        outputs.outputTypes[0] = ScriptType.P2PKH;
        vm.expectRevert(Wallet.WrongOutputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        outputs.amounts = new bytes8[](1);
        outputs.amounts[0] = bytes8(uint64(10));
        outputs.tos = new bytes[](1);
        outputs.tos[0] = bytes("1E1acnMGhWR69vSgH8c4CGEQHVpaVdQdbH");
        outputs.scripts = new bytes[](1);
        vm.expectRevert(Wallet.WrongInputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        inputs.inputTypes = new ScriptType[](1);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.signingPrivateKeys = new uint256[][](1);
        inputs.signingPrivateKeys[0] = new uint256[](1);
        inputs.signingPrivateKeys[0][0] = 2;

        bytes memory data = abi.encodeCall(Wallet.sendTransaction, (node, inputs, outputs));
        // non existent Script type
        data[291] = 0x04;

        (bool s,) = address(mock).call(data);
        assertFalse(s);
    }

    function _getInputs() internal pure returns (Wallet.InputArgs memory inputs) {
        inputs.inputTypes = new ScriptType[](4);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.inputTypes[1] = ScriptType.P2SH;
        inputs.inputTypes[2] = ScriptType.P2WPKH;
        inputs.inputTypes[3] = ScriptType.P2WSH;

        inputs.signingPrivateKeys = new uint256[][](4);
        inputs.signingPrivateKeys[0] = new uint256[](1);
        inputs.signingPrivateKeys[2] = new uint256[](1);
        inputs.signingPrivateKeys[1] = new uint256[](3);
        inputs.signingPrivateKeys[3] = new uint256[](3);
        for (uint256 i = 1; i < 3; ++i) {
            inputs.signingPrivateKeys[1][i] = i;
            inputs.signingPrivateKeys[3][i] = i;
        }

        inputs.txIds = new bytes32[](4);
        inputs.txIds[0] = keccak256("id1");
        inputs.txIds[1] = keccak256("id2");
        inputs.txIds[2] = keccak256("id3");
        inputs.txIds[3] = keccak256("id4");

        inputs.vouts = new bytes4[](4);
        inputs.vouts[0] = bytes4(uint32(0));
        inputs.vouts[1] = bytes4(uint32(2));
        inputs.vouts[2] = bytes4(uint32(1));
        inputs.vouts[3] = bytes4(uint32(3));
    }

    function _getOutputs() internal view returns (Wallet.OutputArgs memory outputs) {
        outputs.outputTypes = new ScriptType[](4);
        outputs.outputTypes[0] = ScriptType.P2PKH;
        outputs.outputTypes[1] = ScriptType.P2SH;
        outputs.outputTypes[2] = ScriptType.P2WPKH;
        outputs.outputTypes[3] = ScriptType.P2WSH;

        outputs.amounts = new bytes8[](4);
        outputs.amounts[0] = bytes8(uint64(100));
        outputs.amounts[1] = bytes8(uint64(200));
        outputs.amounts[2] = bytes8(uint64(300));
        outputs.amounts[3] = bytes8(uint64(400));
        outputs.tos = new bytes[](4);
        outputs.tos[0] = bytes(mock.getAddress(ScriptType.P2PKH, 1, true));
        outputs.tos[2] = bytes(mock.getAddress(ScriptType.P2WPKH, 1, true));
        outputs.scripts = new bytes[](4);
    }

    function _addTransaction(bool isSegwit, bytes32 _txId, bytes4 _vout, bytes memory _scriptPubKey) internal {
        Transaction memory transaction = Transaction({
            isSegwit: isSegwit,
            version: 0x00000001,
            inputs: new TxInput[](0),
            outputs: new TxOutput[](uint32(_vout) + 1),
            locktime: 0,
            witness: new bytes[][](0)
        });
        transaction.outputs[uint32(_vout)].amount = bytes8(uint64(1000));
        transaction.outputs[uint32(_vout)].scriptPubKey = _scriptPubKey;
        node.addTransaction(_txId, transaction);
        node.addUTXO(_txId, _vout);
    }
}
