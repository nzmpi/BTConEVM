// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import "../src/lib/Utils.sol";

contract TestUtils is BaseTest {
    using Utils for bytes;

    bytes[6] data = [
        bytes(""),
        hex"00",
        hex"2a",
        hex"deadbeef",
        hex"2f7928068d9b8596d05493a00cd4b0b2bcdefc7523dc7beaf27618a0e6c90e43",
        hex"c5d0837b49d3ab65cbdfbfa2d1772b9b0f9420c32d85df192e9ad2b3d6fa8490000e84d257536cc1d505c31dbc0d9ad730079fe7afbe19d171a7adb0629c0d78c8"
    ];

    function test_hash160() public view {
        bytes32[6] memory expected = [
            bytes32(hex"b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"),
            hex"9f7fd096d37ed2c0e3f7f0cfc924beef4ffceb68",
            hex"807e59ee43b1c51fa5627ec65fe284cc95d218ba",
            hex"f04df4c4b30d2b7ac6e1ed2445aeb12a9cb4d2ec",
            hex"7de90645a59d6336f9392ff0a0e2f125b670f77b",
            hex"ac7f604620aa1340c3b9d43fb40842ddeda161c6"
        ];

        for (uint256 i; i < data.length; ++i) {
            assertEq(data[i].hash160(), expected[i], "Should correctly hash160 data");
        }
    }

    function test_hash256() public view {
        bytes32[6] memory expected = [
            bytes32(hex"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
            hex"1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a",
            hex"ff122c0ea37f12c5c0f330b2616791df8cb8cc8f1114304afbf0cff5d79cec54",
            hex"281dd50f6f56bc6e867fe73dd614a73c55a647a479704f64804b574cafb0f5c5",
            hex"4b63f6086f6c55dca9d786a5c3f8f2f68e88d0f535c0e832babc7812fd18789b",
            hex"49b5a743ead403ed470374a143447e1377a87f953fbbdcb5b8f04a09a917241e"
        ];

        for (uint256 i; i < data.length; ++i) {
            assertEq(data[i].hash256(), expected[i], "Should correctly hash256 data");
        }
    }

    function test_reverse_endian() public view {
        bytes[6] memory littleEndians = [
            bytes(hex""),
            hex"00",
            hex"2a",
            hex"efbeadde",
            hex"430ec9e6a01876f2ea7bdc2375fcdebcb2b0d40ca09354d096859b8d0628792f",
            hex"c8780d9c62b0ada771d119beafe79f0730d79a0dbc1dc305d5c16c5357d2840e009084fad6b3d29a2e19df852dc320940f9b2b77d1a2bfdfcb65abd3497b83d0c5"
        ];

        for (uint256 i; i < data.length; ++i) {
            assertEq(data[i].convertEndian(), littleEndians[i], "Should correctly convert to little endian");
            assertEq(littleEndians[i].convertEndian(), data[i], "Should correctly convert to big endian");
        }
    }
}
