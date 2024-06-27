// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";
import {SigLib} from "../src/lib/SigLib.sol";
import "../src/lib/Structs.sol";

contract TestSerialLib is BaseTest {
    using SerialLib for Point;
    using SerialLib for Signature;
    using SerialLib for Transaction;
    using SerialLib for bytes;
    using SerialLib for uint256;
    using SigLib for uint256;
    using ECBTC for uint256;

    bytes[3] rawTxs = [
        bytes(
            hex"010000000130303ea774da061109b6f5b0cafc909e6abacf6a52501c71ab9f627b174cea5901000000d90047304402203285484f30722560cfd2c8f346c58be14791ac2859b9ef5aebd31373b9d9ed3802202a40bf31a4a297ba3130920707a2d5315019f33cd175270c198e81727460c96401473044022001888d61eb5d3d5528098531a7dbdb5233748712f069f022a2135e6175bb66a9022064860cb4fb71c3879dce3835765b7f76dbf35621f55729b8c69623e55d13811f01475221022b6dc4281a12a37a00ab920fd9ab1d4b509e288122cf406cd3d0bfb2f5471706210392e4ecdd0af74a2d05b9448343b22fac173c1618c62caf2039efb09c7e67f2d452aeffffffff02b08549030000000017a914b4eef9a952db30866728f788bb469bae8d5fc52687d5df87370000000017a91483e02ab859c6ab1e4ee45b20492eaca173f0b6fb8700000000"
        ),
        hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0f04bedf061a02d405062f503253482fffffffff0100f2052a0100000043410450d5ef5bb3d8a893a4b1fcf2e9d8f898d782fbf22a887f3fbafd22b06d225a5754be9b2cd0d00ee2c3715bfced2e403a6e0d1bf2716ebfd6e6f9ddac1924b6e7ac00000000",
        hex"01000000035f6b1748d9a33b20dd763b9bea17d21f7ea3825a3a11269e4af2aebde8773367000000006c493046022100ed23c8cbb485acd3c073137803584b2a2c91f350d17b54bd1a10a4b814dfad44022100a567ba44f3a3b0769ae96b9af42f4a33827eaa92f5c40deb5886e0009a70f39d012102e2d7f7486ced79f3a4fcc26e4848bd2de484397ba8df365d468acbeecd3562b8ffffffffd7bbaf80903175e219445663b3d23438e8bbcd876785eede9383b81061576966000000006b483045022100e7ad48a20853c7cc1f419589407173b5e82c37e5715f7bc08ed6682381b0adcc0220200ec21da4a684f870bc8065f8a92e669421ca4c747278cc7a0aa5ad44b6555401210342dd1c67748c439ba4567a325c842caa3a16ba5200e730c47af2e5aa581903edffffffffa9fbff9f4dccc331d2bbca29fe1bf6b97f724e344a20c7f7b872732715ca0e3c000000006b483045022100b473b18f9942a9097e5e8677fd4c0442458c193770a65de258928c9f1d9478e902201f41799ef679577fdf0b2783962d1f64da1f828d994991afdff5465bfd8970e9012102f14306fcfc9a8138cc86469c5d2b40f28d885a19faf45b2be6578ea10e910252ffffffff020084d717000000001976a914f5bc94a48ad7f290c58b4fb970514cbf99daf30b88ac47420f00000000001976a914f094dc8e530cdc17221fc936399fcf0da5c3cb4a88ac00000000"
    ];

    function test_serializePublicKey() public view {
        bytes memory result = pubKey.serializePublicKey(false);
        bytes memory expected = bytes.concat(bytes1(0x04), bytes32(pubKey.x), bytes32(pubKey.y));

        assertEq(result, expected, "Uncompressed public key should be serialized correctly");

        result = pubKey.serializePublicKey(true);
        expected = bytes.concat(bytes1(0x03), bytes32(pubKey.x));
        assertEq(result, expected, "Compressed public key should be serialized correctly");
    }

    function test_fuzz_serializePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
        Point memory pubKey_ = _privateKey.mulG();
        bytes memory result = pubKey_.serializePublicKey(_isCompressed);
        bytes memory expected;
        if (_isCompressed) {
            if (pubKey_.y % 2 == 0) {
                expected = bytes.concat(bytes1(0x02), bytes32(pubKey_.x));
            } else {
                expected = bytes.concat(bytes1(0x03), bytes32(pubKey_.x));
            }
            assertEq(result, expected, "Compressed public key should be serialized correctly");
        } else {
            expected = bytes.concat(bytes1(0x04), bytes32(pubKey_.x), bytes32(pubKey_.y));
            assertEq(result, expected, "Uncompressed public key should be serialized correctly");
        }
    }

    function test_parsePublicKey() public {
        bytes memory PKSerlial = pubKey.serializePublicKey(false);
        Point memory result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong uncompressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong uncompressed public key y-coordinate");

        PKSerlial = pubKey.serializePublicKey(true);
        result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong compressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong compressed public key y-coordinate");

        // multiple reverts don't work with internal function calls
        Mock mock = new Mock();

        PKSerlial = hex"04fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);

        PKSerlial = hex"02fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);

        PKSerlial = hex"fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);
    }

    function test_fuzz_parsePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
        Point memory pubKey_ = _privateKey.mulG();
        Point memory result = pubKey_.serializePublicKey(_isCompressed).parsePublicKey();
        assertEq(result.x, pubKey_.x, "Wrong public key x-coordinate");
        assertEq(result.y, pubKey_.y, "Wrong public key y-coordinate");
    }

    function test_serializeSignature() public view {
        Signature memory sig = messageHash.sign(privateKey);
        bytes memory result = sig.serializeSignature();
        bytes memory expected =
            hex"3046022100bed017bc6f4c80dbffd97ae753b58b597c1b71334de814cd59f482303b29425f022100966d4754727615e27d969afa11a72f95bd92280981dee958f50fce3555578245";
        assertEq(result, expected, "Signature should be serialized correctly");

        sig = anotherMessageHash.sign(anotherPrivateKey);
        result = sig.serializeSignature();
        expected =
            hex"304402203bb237e75196b68bec2c415c2efde31364557a50681df03bbc1b6bd3dfcb4d4602203a3ec12e15d72a071b042a4e59cf52ec4f5b2fc664d3ff5f82be08c32e2d4553";
        assertEq(result, expected, "Another signature should be serialized correctly");
    }

    function test_parseSignature() public view {
        Signature memory sig = messageHash.sign(privateKey);
        bytes memory sigSerial = sig.serializeSignature();
        Signature memory result = sigSerial.parseSignature();
        assertEq(result.r, sig.r, "Wrong signature r");
        assertEq(result.s, sig.s, "Wrong signature s");

        sig = messageHash.sign(anotherPrivateKey);
        sigSerial = sig.serializeSignature();
        result = sigSerial.parseSignature();
        assertEq(result.r, sig.r, "Wrong another signature r");
        assertEq(result.s, sig.s, "Wrong another signature s");
    }

    function test_fuzz_parseSignature(uint256 _privateKey) public view {
        Signature memory sig = messageHash.sign(_privateKey);
        Signature memory result = sig.serializeSignature().parseSignature();
        assertEq(result.r, sig.r, "Wrong signature r");
        assertEq(result.s, sig.s, "Wrong signature s");
    }

    function test_serializeTransaction() public view {
        for (uint256 i; i < rawTxs.length; ++i) {
            assertEq(rawTxs[i].parseTransaction().serializeTransaction(), rawTxs[i], "Wrong serialized transaction");
        }
    }

    function test_parseTransaction() public view {
        Transaction memory resTx = rawTxs[0].parseTransaction();
        assertEq(resTx.version, hex"00000001", "Wrong version 0");
        assertEq(resTx.inputs.length, 1, "Wrong number of inputs 0");
        assertEq(
            resTx.inputs[0].txId, hex"59ea4c177b629fab711c50526acfba6a9e90fccab0f5b6091106da74a73e3030", "Wrong txId 0"
        );
        assertEq(resTx.inputs[0].vout, hex"00000001", "Wrong vout 0");
        assertEq(
            resTx.inputs[0].scriptSig,
            hex"d90047304402203285484f30722560cfd2c8f346c58be14791ac2859b9ef5aebd31373b9d9ed3802202a40bf31a4a297ba3130920707a2d5315019f33cd175270c198e81727460c96401473044022001888d61eb5d3d5528098531a7dbdb5233748712f069f022a2135e6175bb66a9022064860cb4fb71c3879dce3835765b7f76dbf35621f55729b8c69623e55d13811f01475221022b6dc4281a12a37a00ab920fd9ab1d4b509e288122cf406cd3d0bfb2f5471706210392e4ecdd0af74a2d05b9448343b22fac173c1618c62caf2039efb09c7e67f2d452ae",
            "Wrong scriptSig 0"
        );
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 0");
        assertEq(resTx.outputs.length, 2, "Wrong number of outputs 0");
        assertEq(resTx.outputs[0].amount, hex"00000000034985b0", "Wrong amount 0 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"17a914b4eef9a952db30866728f788bb469bae8d5fc52687",
            "Wrong scriptPubKey 0 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"000000003787dfd5", "Wrong amount 0 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"17a91483e02ab859c6ab1e4ee45b20492eaca173f0b6fb87",
            "Wrong scriptPubKey 0 at 1"
        );
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 0");

        resTx = rawTxs[1].parseTransaction();
        assertEq(resTx.version, hex"00000001", "Wrong version 1");
        assertEq(resTx.inputs.length, 1, "Wrong number of inputs 1");
        assertEq(
            resTx.inputs[0].txId, hex"0000000000000000000000000000000000000000000000000000000000000000", "Wrong txId 1"
        );
        assertEq(resTx.inputs[0].vout, hex"ffffffff", "Wrong vout 1");
        assertEq(resTx.inputs[0].scriptSig, hex"0f04bedf061a02d405062f503253482f", "Wrong scriptSig 1");
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 1");
        assertEq(resTx.outputs.length, 1, "Wrong number of outputs 1");
        assertEq(resTx.outputs[0].amount, hex"000000012a05f200", "Wrong amount 1");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"43410450d5ef5bb3d8a893a4b1fcf2e9d8f898d782fbf22a887f3fbafd22b06d225a5754be9b2cd0d00ee2c3715bfced2e403a6e0d1bf2716ebfd6e6f9ddac1924b6e7ac",
            "Wrong scriptPubKey 1"
        );
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 1");

        resTx = rawTxs[2].parseTransaction();
        assertEq(resTx.version, hex"00000001", "Wrong version 2");
        assertEq(resTx.inputs.length, 3, "Wrong number of inputs 2");
        assertEq(
            resTx.inputs[0].txId,
            hex"673377e8bdaef24a9e26113a5a82a37e1fd217ea9b3b76dd203ba3d948176b5f",
            "Wrong txId 2 at 0"
        );
        assertEq(resTx.inputs[0].vout, hex"00000000", "Wrong vout 2 at 0");
        assertEq(
            resTx.inputs[0].scriptSig,
            hex"6c493046022100ed23c8cbb485acd3c073137803584b2a2c91f350d17b54bd1a10a4b814dfad44022100a567ba44f3a3b0769ae96b9af42f4a33827eaa92f5c40deb5886e0009a70f39d012102e2d7f7486ced79f3a4fcc26e4848bd2de484397ba8df365d468acbeecd3562b8",
            "Wrong scriptSig 2 at 0"
        );
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 2 at 0");
        assertEq(
            resTx.inputs[1].txId,
            hex"6669576110b88393deee856787cdbbe83834d2b363564419e275319080afbbd7",
            "Wrong txId 2 at 1"
        );
        assertEq(resTx.inputs[1].vout, hex"00000000", "Wrong vout 2 at 1");
        assertEq(
            resTx.inputs[1].scriptSig,
            hex"6b483045022100e7ad48a20853c7cc1f419589407173b5e82c37e5715f7bc08ed6682381b0adcc0220200ec21da4a684f870bc8065f8a92e669421ca4c747278cc7a0aa5ad44b6555401210342dd1c67748c439ba4567a325c842caa3a16ba5200e730c47af2e5aa581903ed",
            "Wrong scriptSig 2 at 1"
        );
        assertEq(resTx.inputs[1].sequence, hex"ffffffff", "Wrong sequence 2 at 1");
        assertEq(
            resTx.inputs[2].txId,
            hex"3c0eca15277372b8f7c7204a344e727fb9f61bfe29cabbd231c3cc4d9ffffba9",
            "Wrong txId 2 at 2"
        );
        assertEq(resTx.inputs[2].vout, hex"00000000", "Wrong vout 2 at 2");
        assertEq(
            resTx.inputs[2].scriptSig,
            hex"6b483045022100b473b18f9942a9097e5e8677fd4c0442458c193770a65de258928c9f1d9478e902201f41799ef679577fdf0b2783962d1f64da1f828d994991afdff5465bfd8970e9012102f14306fcfc9a8138cc86469c5d2b40f28d885a19faf45b2be6578ea10e910252",
            "Wrong scriptSig 2 at 2"
        );
        assertEq(resTx.inputs[2].sequence, hex"ffffffff", "Wrong sequence 2 at 2");
        assertEq(resTx.outputs.length, 2, "Wrong number of outputs 2");
        assertEq(resTx.outputs[0].amount, hex"0000000017d78400", "Wrong amount 2 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"1976a914f5bc94a48ad7f290c58b4fb970514cbf99daf30b88ac",
            "Wrong scriptPubKey 2 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"00000000000f4247", "Wrong amount 2 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"1976a914f094dc8e530cdc17221fc936399fcf0da5c3cb4a88ac",
            "Wrong scriptPubKey 2 at 1"
        );
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 2");
    }
}

contract Mock {
    using SerialLib for bytes;

    function parsePublicKey(bytes memory _data) external pure returns (Point memory) {
        return _data.parsePublicKey();
    }
}
