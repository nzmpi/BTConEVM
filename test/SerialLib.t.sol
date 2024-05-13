// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";

contract TestSerialLib is BaseTest {
    using SerialLib for Point;
    using SerialLib for bytes;

    function test_serializePublicKey() public view {
        bytes memory result = pubKey.serializePublicKey(false);
        bytes memory expected = bytes.concat(bytes1(0x04), bytes32(pubKey.x), bytes32(pubKey.y));

        assertEq(result, expected, "Uncompressed public key should be serialized correctly");

        result = pubKey.serializePublicKey(true);
        expected = bytes.concat(bytes1(0x03), bytes32(pubKey.x));
        assertEq(result, expected, "Compressed public key should be serialized correctly");
    }

    function test_parsPublicKeye() public {
        bytes memory PKSerlial = pubKey.serializePublicKey(false);
        Point memory result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong uncompressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong uncompressed public key y-coordinate");

        PKSerlial = pubKey.serializePublicKey(true);
        result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong compressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong compressed public key y-coordinate");

        PKSerlial = hex"04fff3423acb";
        vm.expectRevert("Wrong data length");
        PKSerlial.parsePublicKey();

        PKSerlial = hex"02fff3423acb";
        vm.expectRevert("Wrong data length");
        PKSerlial.parsePublicKey();

        PKSerlial = hex"fff3423acb";
        vm.expectRevert(SerialLib.WrongPrefix.selector);
        PKSerlial.parsePublicKey();
    }
}
