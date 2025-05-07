// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Varint} from "../src/lib/Varint.sol";
import "./utils/BaseTest.sol";

contract TestVarint is BaseTest {
    using Varint for *;

    error WrongRead();

    uint256[6] data = [0, 201, 253, 65500, 3500000000, 18446744073709551615];

    function test_toVarint() public {
        bytes[6] memory expected =
            [bytes(hex"00"), hex"c9", hex"fdfd00", hex"fddcff", hex"fe00c39dd0", hex"ffffffffffffffffff"];
        for (uint256 i; i < data.length; i++) {
            assertEq(data[i].toVarint(), expected[i], "Should correctly convert to varint");
        }

        vm.expectRevert(Varint.VarintOverflow.selector);
        (uint256(type(uint64).max) + 1).toVarint();
    }

    function test_fromVarint() public {
        for (uint256 i; i < data.length; i++) {
            (uint256 result,) = data[i].toVarint().fromVarint(0);
            assertEq(result, data[i], "Should correctly convert from varint");
        }

        // multiple reverts don't work with internal function calls
        Mock mock = new Mock();

        vm.expectRevert(Varint.NotVarint.selector);
        mock.fromVarint(hex"");

        vm.expectRevert(WrongRead.selector);
        mock.fromVarint(hex"fdfd");
    }

    function test_fuzz_fromVarint(uint256 x) public {
        if (x > type(uint64).max) {
            vm.expectRevert(Varint.VarintOverflow.selector);
            x.toVarint();
        }
        (uint256 result,) = x.toVarint().fromVarint(0);
        assertEq(result, x, "Should correctly fuzz");
    }
}

contract Mock {
    using Varint for bytes;

    function fromVarint(bytes memory _data) external pure returns (uint256 result) {
        (result,) = _data.fromVarint(0);
    }
}
