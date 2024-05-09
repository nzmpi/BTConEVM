// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./EllipticCurve.sol";

library ECBTC {
    uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 constant AA = 0;
    uint256 constant BB = 7;
    uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

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

    function mul(uint256 _x, uint256 _y) internal pure returns (uint256 res) {
        res = (_x * _y) % N;
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
    function add(Point memory _p1, Point memory _p2) internal pure returns (Point memory p) {
        (p.x, p.y) = EllipticCurve.ecAdd(_p1.x, _p1.y, _p2.x, _p2.y, AA, PP);
    }

    function inv(uint256 _x) internal pure returns (uint256 xInv) {
        xInv = EllipticCurve.invMod(_x, N);
    }
}
