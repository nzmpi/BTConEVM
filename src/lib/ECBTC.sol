// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./EllipticCurve.sol";

library ECBTC {
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    struct Point {
        uint256 x;
        uint256 y;
    }

    /**
     * @dev Multiplies scalar and an ec point
     * @param _k - The scalar
     * @param _p - The point
     * @return p - The result
     */
    function mul(uint256 _k, Point calldata _p) internal pure returns (Point memory p) {
        (p.x, p.y) = EllipticCurve.ecMul(_k, _p.x, _p.y, AA, PP);
    }

    /**
     * @dev Multiplies scalar and a generator point
     * @param _k - The scalar
     * @return p - The result
     */
    function mulG(uint256 _k) internal pure returns (Point memory p) {
        (p.x, p.y) = EllipticCurve.ecMul(_k, GX, GY, AA, PP);
    }

    /**
     * @dev Adds two ec points
     * @param _p1 - The first point
     * @param _p2 - The second point
     * @return p - The result
     */
    function add(Point calldata _p1, Point calldata _p2) internal pure returns (Point memory p) {
        (p.x, p.y) = EllipticCurve.ecAdd(_p1.x, _p1.y, _p2.x, _p2.y, AA, PP);
    }
}
