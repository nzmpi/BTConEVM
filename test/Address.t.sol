// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {Address} from "../src/lib/Address.sol";
import {ScriptType} from "../src/lib/Types.sol";

contract MockAddress {
    using Address for bytes;

    function checksum(bytes calldata _address) external pure {
        _address.checksum();
    }

    function getHashFromAddress(bytes memory _address) external pure {
        _address.getHashFromAddress();
    }
}

contract TestAddress is BaseTest {
    using Address for bytes;

    MockAddress mock;

    bytes[6] hashes = [
        bytes(hex"ec31156c8a1ec06c171a7da0ac5b33c0606aed3b"),
        hex"732c046d1c88f13e7ec1f9660c716b5a048ec40c",
        hex"b802fa30644ce69a997a6dcb57d246240bf5556b",
        hex"905d0ae5e05581fbe7e2e32f7a5b22782ddf2102d75baa543c42bc09ec3e825e",
        hex"b754de4bf41e9820022f5cdf12f9cf78a759344b53ab02299ce926cce8ec33b7",
        hex"7a52af5f259b41ba0def7632c55d1cbd9cfd93847a9cdeecd0ac9b8cd981b761"
    ];
    string[24] addresses = [
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
        "2NA2BtStn5Ej9rtrszWovqGAbKFj3wXUYRk",
        "bc1qasc32my2rmqxc9c60ks2ckencpsx4mfmyxtfv0",
        "bc1qwvkqgmgu3rcnulkpl9nqcutttgzga3qvqtgx9p",
        "bc1qhqp05vryfnnf4xt6dh9405jxys9l24ttkk36s6",
        "tb1qasc32my2rmqxc9c60ks2ckencpsx4mfmwqs6hu",
        "tb1qwvkqgmgu3rcnulkpl9nqcutttgzga3qv2dn47j",
        "tb1qhqp05vryfnnf4xt6dh9405jxys9l24ttus2ftf",
        "bc1qjpws4e0q2kqlhelzuvhh5kez0qka7ggz6ad654pug27qnmp7sf0qgxuf2n",
        "bc1qka2dujl5r6vzqq30tn0397w00zn4jdzt2w4sy2vuaynve68vxwmslc5wkr",
        "bc1q0ff27he9ndqm5r00wcev2hguhkw0myuy02wdamxs4jdcekvpkasst0wyqa",
        "tb1qjpws4e0q2kqlhelzuvhh5kez0qka7ggz6ad654pug27qnmp7sf0qlw2xsu",
        "tb1qka2dujl5r6vzqq30tn0397w00zn4jdzt2w4sy2vuaynve68vxwmsgszpvv",
        "tb1q0ff27he9ndqm5r00wcev2hguhkw0myuy02wdamxs4jdcekvpkassu8ct6j"
    ];

    function setUp() public {
        mock = new MockAddress();
    }

    function test_getAddress() public view {
        for (uint256 i; i < hashes.length / 2; ++i) {
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

            // P2WPKH mainnet
            assertEq(
                string(hashes[i].getAddress(true, ScriptType.P2WPKH)),
                addresses[i + 12],
                "Wrong address for P2WPKH mainnet"
            );
            // P2WPKH testnet
            assertEq(
                string(hashes[i].getAddress(false, ScriptType.P2WPKH)),
                addresses[i + 15],
                "Wrong address for P2WPKH testnet"
            );

            // P2WSH mainnet
            assertEq(
                string(hashes[i + 3].getAddress(true, ScriptType.P2WSH)),
                addresses[i + 18],
                "Wrong address for P2WSH mainnet"
            );
            // P2WSH testnet
            assertEq(
                string(hashes[i + 3].getAddress(false, ScriptType.P2WSH)),
                addresses[i + 21],
                "Wrong address for P2WSH testnet"
            );
        }
    }

    function test_checksum() public {
        for (uint256 i; i < addresses.length; ++i) {
            bytes(addresses[i]).checksum();
        }

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.checksum(bytes("1NXsGfeFnk3U3QnYGR2CzXAyT7y1HSjKGj"));

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.checksum(bytes("bc1qasc32my2rmqxc9c60ks2ckencpsx4mfmyxtfv2"));

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.getHashFromAddress(bytes("bc1q0ff29he9ndqm5r00wcev2hguhkw0myuy02wdamxs4jdcekvpkasst0wyqa"));
    }

    function test_getHashFromAddress() public {
        for (uint256 i; i < addresses.length - 6; ++i) {
            assertEq(bytes(addresses[i]).getHashFromAddress(), hashes[i % 3], "Wrong hash for address");
        }

        for (uint256 i; i < 6; ++i) {
            assertEq(bytes(addresses[18 + i]).getHashFromAddress(), hashes[i % 3 + 3], "Wrong hash32 for address");
        }

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.getHashFromAddress(bytes("1NXsGfeFnk3U3QnYGR2CzXAyT7y1HSjKGj"));

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.getHashFromAddress(bytes("bc1qasc32my2rmqxc9c60ks2ckencpsx4mfmyxtfv2"));

        vm.expectRevert(Address.ChecksumFailed.selector);
        mock.getHashFromAddress(bytes("bc1q0ff29he9ndqm5r00wcev2hguhkw0myuy02wdamxs4jdcekvpkasst0wyqa"));
    }
}
