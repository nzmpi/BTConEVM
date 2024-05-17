// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./EllipticCurve.sol";
import {Point} from "./Structs.sol";

/**
 * @title Secp256k1 Elliptic Curve
 * @dev A wrapper for elliptic curve operations using secp256k1 parameters.
 * @author https://github.com/nzmpi
 */
library ECBTC {
    using EllipticCurve for uint256;

    uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 constant A = 0;
    uint256 constant B = 7;
    uint256 constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /**
     * @dev Modulo N
     * @param _x - The number
     * @return _x mod N
     */
    function mod(uint256 _x) internal pure returns (uint256) {
        return _x % N;
    }

    /**
     * @dev Adds two scalars mod N
     * @param _x - The first scalar
     * @param _y - The second scalar
     * @return res - The result
     */
    function add(uint256 _x, uint256 _y) internal pure returns (uint256 res) {
        res = addmod(_x, _y, N);
    }

    /**
     * @dev Multiplies two scalars mod N
     * @param _x - The first scalar
     * @param _y - The second scalar
     * @return res - The result
     */
    function mul(uint256 _x, uint256 _y) internal pure returns (uint256 res) {
        res = mulmod(_x, _y, N);
    }

    /**
     * @dev Multiplies scalar and a generator point
     * @param _k - The scalar
     * @return p - The result
     */
    function mulG(uint256 _k) internal pure returns (Point memory p) {
        (p.x, p.y) = _k.ecMul(GX, GY, A, P);
    }

    /**
     * @dev Inverts a scalar, such as x * xInv = 1 mod N
     * @param _x - The scalar
     * @return xInv - The result
     */
    function inv(uint256 _x) internal pure returns (uint256 xInv) {
        xInv = _x.invMod(N);
    }

    /**
     * @dev Multiplies scalar and an ec point
     * @param _k - The scalar
     * @param _p - The point
     * @return p - The result
     */
    function mul(uint256 _k, Point memory _p) internal pure returns (Point memory p) {
        (p.x, p.y) = _k.ecMul(_p.x, _p.y, A, P);
    }

    /**
     * @dev Adds two ec points
     * @param _p1 - The first point
     * @param _p2 - The second point
     * @return p - The result
     */
    function add(Point memory _p1, Point memory _p2) internal pure returns (Point memory p) {
        (p.x, p.y) = _p1.x.ecAdd(_p1.y, _p2.x, _p2.y, A, P);
    }

    function deriveY(uint256 _x, bytes1 _prefix) internal pure returns (uint256 y) {
        y = EllipticCurve.deriveY(uint8(_prefix), _x, A, B, P);
    }
}
