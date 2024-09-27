// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Address} from "../src/lib/Address.sol";
import "./utils/BaseTest.sol";
import {MockNode} from "./Node.t.sol";
import "../src/lib/Structs.sol";
import {ScriptType} from "../src/lib/Types.sol";
import "../src/lib/Utils.sol";
import {Wallet} from "../src/Wallet.sol";

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
            inputs.txIds[0],
            inputs.vouts[0],
            bytes.concat(
                bytes1(0x76),
                bytes1(0xa9),
                bytes1(0x14),
                bytes(mock.getP2PKHAddress(0, true, true)).getHashFromAddress(),
                bytes1(0x88),
                bytes1(0xac)
            )
        );
        _addTransaction(
            inputs.txIds[1],
            inputs.vouts[1],
            bytes.concat(bytes1(0xa9), bytes1(0x14), mock.getRedeemScript(3).hash160(), bytes1(0x87))
        );
        bytes32 txId = mock.sendTransaction(node, inputs, outputs);

        // should be able to use the previous output
        inputs.inputTypes = new ScriptType[](1);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.signingPrivateKeys = new uint256[][](1);
        uint256[] memory privateKeys = new uint256[](1);
        privateKeys[0] = 1;
        inputs.signingPrivateKeys[0] = privateKeys;
        inputs.txIds = new bytes32[](1);
        inputs.txIds[0] = txId;
        inputs.vouts = new bytes4[](1);
        inputs.areCompressed = new bool[](1);
        inputs.areCompressed[0] = true;

        outputs.outputTypes = new ScriptType[](1);
        outputs.outputTypes[0] = ScriptType.P2PKH;
        outputs.amounts = new bytes8[](1);
        outputs.amounts[0] = bytes8(uint64(10));
        outputs.tos = new bytes[](1);
        outputs.tos[0] = bytes("1E1acnMGhWR69vSgH8c4CGEQHVpaVdQdbH");
        outputs.redeemScripts = new bytes[](1);

        mock.sendTransaction(node, inputs, outputs);
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
        outputs.redeemScripts = new bytes[](1);
        vm.expectRevert(Wallet.WrongInputData.selector);
        mock.sendTransaction(node, inputs, outputs);

        inputs.inputTypes = new ScriptType[](1);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.signingPrivateKeys = new uint256[][](1);
        uint256[] memory privateKeys = new uint256[](1);
        privateKeys[0] = 2;
        inputs.signingPrivateKeys[0] = privateKeys;
        inputs.areCompressed = new bool[](1);
        inputs.areCompressed[0] = true;

        bytes memory data = abi.encodeCall(Wallet.sendTransaction, (node, inputs, outputs));
        // non existent Script type
        data[323] = 0x02;

        (bool s,) = address(mock).call(data);
        assertFalse(s);
    }

    function _getInputs() internal pure returns (Wallet.InputArgs memory inputs) {
        inputs.inputTypes = new ScriptType[](2);
        inputs.inputTypes[0] = ScriptType.P2PKH;
        inputs.inputTypes[1] = ScriptType.P2SH;

        inputs.signingPrivateKeys = new uint256[][](2);
        uint256[] memory privateKeys = new uint256[](1);
        privateKeys[0] = 0;
        inputs.signingPrivateKeys[0] = privateKeys;
        privateKeys = new uint256[](3);
        privateKeys[0] = 0;
        privateKeys[1] = 1;
        privateKeys[2] = 2;
        inputs.signingPrivateKeys[1] = privateKeys;

        inputs.txIds = new bytes32[](2);
        inputs.txIds[0] = keccak256("id1");
        inputs.txIds[1] = keccak256("id2");

        inputs.vouts = new bytes4[](2);
        inputs.vouts[0] = bytes4(uint32(0));
        inputs.vouts[1] = bytes4(uint32(2));

        inputs.areCompressed = new bool[](2);
        inputs.areCompressed[0] = true;
        inputs.areCompressed[1] = true;
    }

    function _getOutputs() internal view returns (Wallet.OutputArgs memory outputs) {
        outputs.outputTypes = new ScriptType[](2);
        outputs.outputTypes[0] = ScriptType.P2PKH;
        outputs.outputTypes[1] = ScriptType.P2SH;

        outputs.amounts = new bytes8[](2);
        outputs.amounts[0] = bytes8(uint64(100));
        outputs.amounts[1] = bytes8(uint64(200));
        outputs.tos = new bytes[](2);
        outputs.tos[0] = bytes(mock.getP2PKHAddress(1, true, true));
        outputs.redeemScripts = new bytes[](2);
    }

    function _addTransaction(bytes32 _txId, bytes4 _vout, bytes memory _scriptPubKey) internal {
        Transaction memory transaction = Transaction({
            version: 0x00000001,
            inputs: new TxInput[](0),
            outputs: new TxOutput[](uint32(_vout) + 1),
            locktime: 0
        });
        transaction.outputs[uint32(_vout)].amount = bytes8(uint64(1000));
        transaction.outputs[uint32(_vout)].scriptPubKey = _scriptPubKey;
        node.addTransaction(_txId, transaction);
        node.addUTXO(_txId, _vout);
    }
}
