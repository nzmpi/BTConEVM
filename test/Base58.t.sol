// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import "../src/lib/Base58.sol";

contract TestBase58 is BaseTest {
    using Base58 for bytes;

    bytes[5] data = [
        bytes(hex"00"), // 0
        hex"00000000", // multiple 0's
        hex"deadbeef", // < 32 bytes
        hex"80e0bac72ebe3d0268fc302a1465e38b6d5999c528a7b503f43824ab76ab85c6", // == 32 bytes
        hex"05346cf530ed5973ab8f72055f88d1c300388a0fac6d70bdad6f4bc2b8b3d15ef998d171674c5af45e6283ff2fd46091801100b369b2aeefc8a3aedbb5786d71b85e66acaf813ab057bfbf" // > 32 bytes
    ];

    function test_encode() public {
        bytes[5] memory expected = [
            bytes("1"),
            "1111",
            "6h8cQN",
            "9g5wN7v8y4civ5F53N9FDELupL7eFhNrC9NJmXpSpSx5",
            "7c9JcemMKghg9Hs3t3Qk778fVk6Yct49jVfY167rjyg6xk5HL5ny2rrCB6aHXjmpVioaRggBXrpMk8N8m7ELR3SduFoDuV29xMJNJi"
        ];
        for (uint256 i; i < data.length; ++i) {
            assertEq(data[i].encode(), expected[i], "Should encode data");
        }

        vm.expectRevert(Base58.WrongData.selector);
        bytes(hex"").encode();
    }

    function test_decode() public {
        for (uint256 i; i < data.length; ++i) {
            assertEq(data[i].encode().decode(), data[i], "Should decode data");
        }

        vm.expectRevert(Base58.WrongData.selector);
        bytes("").decode();

        vm.expectRevert(Base58.NotBase58.selector);
        bytes("0").decode();

        vm.expectRevert(Base58.NotBase58.selector);
        bytes("O").decode();

        vm.expectRevert(Base58.NotBase58.selector);
        bytes("I").decode();

        vm.expectRevert(Base58.NotBase58.selector);
        bytes("l").decode();

        vm.expectRevert(Base58.NotBase58.selector);
        bytes("!").decode();
    }
}
