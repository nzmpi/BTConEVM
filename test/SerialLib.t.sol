// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";
import {SigLib} from "../src/lib/SigLib.sol";
import {Signature} from "../src/lib/Structs.sol";

contract TestSerialLib is BaseTest {
    using SerialLib for Point;
    using SerialLib for Signature;
    using SerialLib for bytes;
    using SerialLib for uint256;
    using SigLib for uint256;
    using ECBTC for uint256;

    function test_serializePublicKey() public view {
        bytes memory result = pubKey.serializePublicKey(false);
        bytes memory expected = bytes.concat(bytes1(0x04), bytes32(pubKey.x), bytes32(pubKey.y));

        assertEq(result, expected, "Uncompressed public key should be serialized correctly");

        result = pubKey.serializePublicKey(true);
        expected = bytes.concat(bytes1(0x03), bytes32(pubKey.x));
        assertEq(result, expected, "Compressed public key should be serialized correctly");
    }

    function test_fuzzing_serializePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
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

    function test_fuzzing_parsePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
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

    function test_fuzzing_parseSignature(uint256 _privateKey) public view {
        Signature memory sig = messageHash.sign(_privateKey);
        Signature memory result = sig.serializeSignature().parseSignature();
        assertEq(result.r, sig.r, "Wrong signature r");
        assertEq(result.s, sig.s, "Wrong signature s");
    }
}

contract Mock {
    using SerialLib for bytes;

    function parsePublicKey(bytes memory _data) external pure returns (Point memory) {
        return _data.parsePublicKey();
    }
}
