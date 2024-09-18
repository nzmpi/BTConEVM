// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {Address} from "../src/lib/Address.sol";
import {ScriptType} from "../src/lib/Types.sol";

contract TestAddress is BaseTest {
    using Address for *;

    bytes20[3] hashes = [
        bytes20(hex"ec31156c8a1ec06c171a7da0ac5b33c0606aed3b"),
        hex"732c046d1c88f13e7ec1f9660c716b5a048ec40c",
        hex"b802fa30644ce69a997a6dcb57d246240bf5556b"
    ];
    string[12] addresses = [
        "1NXsGfefnk3U3QnYGR2CzXAyT7y1HSjKGj",
        "1BVySSFkHUYXzMHzevQw8Bpji39T8GpG8r",
        "1HmxuAUJusuRZwXuCHXTngpPxPEAZpHr58",
        "n33pZijebmUipXG9yyzapSPJK7ZiDUiYij",
        "mr1vjVLj6VynmTmcNVPJx734a2kA2QRt5r",
        "mxHvCDZHiuLgM41WurVqcc2ipNpsXQepP1",
        "3PDtCD97LeMr8aUyPWgoR9XubeFipwytWa",
        "3CBzMykBqNrv5WzRn25XYpBfrZSAjqxWPJ",
        "3JTyphxkTnDof7ELKPC4DKBL6uWt94YRPb",
        "2NEn6Fx58x6sCLN7X4eJg36XAozTtbm9zAk",
        "2N3kCRigDSqNGHJcyT9hQAmAw4ueLU1aqDN",
        "2NA2BtStn5Ej9rtrszWovqGAbKFj3wXUYRk"
    ];

    function test_getAddress() public view {
        for (uint256 i; i < hashes.length; ++i) {
            // P2PKH mainnet
            assertEq(
                string(hashes[i].getAddress(true, ScriptType.P2PKH)), addresses[i], "Wrong address for P2PKH mainnet"
            );
            // P2PKH testnet
            assertEq(
                string(hashes[i].getAddress(false, ScriptType.P2PKH)),
                addresses[i + 3],
                "Wrong address for P2PKH testnet"
            );
            // P2SH mainnet
            assertEq(
                string(hashes[i].getAddress(true, ScriptType.P2SH)), addresses[i + 6], "Wrong address for P2SH mainnet"
            );
            // P2SH testnet
            assertEq(
                string(hashes[i].getAddress(false, ScriptType.P2SH)), addresses[i + 9], "Wrong address for P2SH testnet"
            );
        }
    }

    function test_checksum() public {
        for (uint256 i; i < addresses.length; ++i) {
            bytes(addresses[i]).checksum();
        }

        Mock mock = new Mock();
        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.checksum(bytes("1NXsGfeFnk3U3QnYGR2CzXAyT7y1HSjKGj"));
    }

    function test_getHashFromAddress() public {
        for (uint256 i; i < addresses.length; ++i) {
            assertEq(bytes(addresses[i]).getHashFromAddress(), hashes[i % 3], "Wrong hash for address");
        }

        Mock mock = new Mock();
        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.getHashFromAddress(bytes("1NXsGfeFnk3U3QnYGR2CzXAyT7y1HSjKGj"));
    }
}

contract Mock {
    using Address for bytes;

    function checksum(bytes calldata _address) external pure {
        _address.checksum();
    }

    function getHashFromAddress(bytes memory _address) external pure {
        _address.getHashFromAddress();
    }
}
