// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/lib/Utils.sol";
import "./utils/BaseTest.sol";

contract MockUtils {
    using Utils for *;

    function bytesToUint256(bytes memory _data) external pure returns (uint256 res) {
        return _data.bytesToUint256();
    }

    function readFromMemory(bytes memory _from, uint256 _offset, uint256 _length)
        external
        pure
        returns (bytes memory res)
    {
        return _from.readFromMemory(_offset, _length);
    }

    function getLengthForScript(uint256 _length) external pure returns (bytes memory res) {
        return _length.getLengthForScript();
    }
}

// add new tests

contract TestUtils is BaseTest {
    using Utils for *;

    bytes[6] data = [
        bytes(""),
        hex"00",
        hex"2a",
        hex"deadbeef",
        hex"2f7928068d9b8596d05493a00cd4b0b2bcdefc7523dc7beaf27618a0e6c90e43",
        hex"c5d0837b49d3ab65cbdfbfa2d1772b9b0f9420c32d85df192e9ad2b3d6fa8490000e84d257536cc1d505c31dbc0d9ad730079fe7afbe19d171a7adb0629c0d78c8"
    ];
    bytes[6] numbers = [
        bytes(hex"00"),
        hex"24",
        hex"566ef2",
        hex"ffffffffffffad0f",
        hex"0279f24140c456a5fb24ddea4e3382fa86aa7894b3e79539766ddc60a4647e76",
        hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ];

    MockUtils mock;

    function setUp() public {
        mock = new MockUtils();
    }

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

    function test_convertEndian() public view {
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

        assertEq(
            bytes32(data[4]).convertEndian(),
            bytes32(littleEndians[4]),
            "Should correctly convert bytes32 to little endian"
        );
        assertEq(
            bytes32(littleEndians[4]).convertEndian(),
            bytes32(data[4]),
            "Should correctly convert bytes32 to big endian"
        );
    }

    function test_bytesToUint256() public {
        uint256[6] memory expected = [
            0,
            36,
            5664498,
            18446744073709530383,
            1120086173837929590502398074382113721969058458401023110029408379327383633526,
            115792089237316195423570985008687907853269984665640564039457584007913129639935
        ];
        for (uint256 i; i < numbers.length; ++i) {
            assertEq(numbers[i].bytesToUint256(), expected[i], "Should correctly convert bytes to uint256");
        }

        // multiple reverts don't work with internal function calls
        vm.expectRevert(Utils.WrongLength.selector);
        mock.bytesToUint256(bytes(hex""));

        vm.expectRevert(Utils.WrongLength.selector);
        mock.bytesToUint256(bytes(hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    }

    function test_fuzz_bytesToUint256(bytes calldata x) public {
        if (x.length == 0 || x.length > 32) {
            vm.expectRevert(Utils.WrongLength.selector);
            x.bytesToUint256();
        } else {
            bytes memory res = x.bytesToUint256().uint256ToBytes();
            uint256 xLen = x.length;
            if (res.length != xLen) {
                assembly {
                    let resLen := mload(res)
                    mstore(res, xLen)
                    let start := add(res, 32)
                    let shift := mul(sub(xLen, resLen), 8)
                    mstore(start, shr(shift, mload(start)))
                }
            }
            assertEq(res, x, "Should correctly fuzz bytes");
        }
    }

    function test_uint256ToBytes() public view {
        for (uint256 i; i < numbers.length; ++i) {
            assertEq(
                numbers[i].bytesToUint256().uint256ToBytes(), numbers[i], "Should correctly convert uint256 to bytes"
            );
        }
    }

    function test_fuzz_uint256ToBytes(uint256 x) public pure {
        assertEq(x.uint256ToBytes().bytesToUint256(), x, "Should correctly fuzz uint256");
    }

    function test_readFromMemory() public {
        assertEq(data[1].readFromMemory(0, 1), hex"00", "Wrong read 1");
        assertEq(data[3].readFromMemory(2, 2), hex"beef", "Wrong read 2");
        assertEq(data[5].readFromMemory(10, 7), hex"bfa2d1772b9b0f", "Wrong read 3");
        assertEq(
            data[5].readFromMemory(38, 27), hex"6cc1d505c31dbc0d9ad730079fe7afbe19d171a7adb0629c0d78c8", "Wrong read 4"
        );

        // multiple reverts don't work with internal function calls
        vm.expectRevert(Utils.WrongRead.selector);
        mock.readFromMemory(data[0], 0, 1);

        vm.expectRevert(Utils.WrongRead.selector);
        mock.readFromMemory(data[4], 31, 2);

        vm.expectRevert(Utils.WrongRead.selector);
        mock.readFromMemory(data[4], 35, 2);
    }

    function test_getLengthForScript() public {
        uint256[10] memory inputs = [
            0,
            3,
            0x4b,
            0x4c,
            255,
            400,
            520,
            0xa4545fe33c,
            0x0279f24140c456a5fb24ddea4e3382fa86aa7894b3e79539766ddc60a4647e76,
            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        ];
        bytes[7] memory expected = [bytes(hex"00"), hex"03", hex"4b", hex"4c4c", hex"4cff", hex"4d0190", hex"4d0208"];

        for (uint256 i; i < inputs.length; ++i) {
            if (inputs[i] > 520) {
                vm.expectRevert(Utils.WrongLength.selector);
                mock.getLengthForScript(inputs[i]);
            } else {
                assertEq(inputs[i].getLengthForScript(), expected[i]);
            }
        }
    }

    function test_getNumberForScript() public pure {
        uint256[12] memory inputs = [
            0,
            1,
            3,
            16,
            17,
            0x4c,
            255,
            400,
            520,
            0xa4545fe33c,
            0x0279f24140c456a5fb24ddea4e3382fa86aa7894b3e79539766ddc60a4647e76,
            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        ];
        bytes[12] memory expected = [
            bytes(hex""),
            hex"51",
            hex"53",
            hex"60",
            hex"0111",
            hex"014c",
            hex"01ff",
            hex"020190",
            hex"020208",
            hex"05a4545fe33c",
            hex"200279f24140c456a5fb24ddea4e3382fa86aa7894b3e79539766ddc60a4647e76",
            hex"20ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ];

        for (uint256 i; i < inputs.length; ++i) {
            assertEq(inputs[i].getNumberForScript(), expected[i]);
        }
    }
}
