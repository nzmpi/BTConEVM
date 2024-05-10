// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECBTC} from "./ECBTC.sol";

/**
 * @title SigLib - Signature Library
 * @notice Takes care of signing and verifying signatures
 */
library SigLib {
    struct Signature {
        uint256 r;
        uint256 s;
    }

    /**
     * @notice Signs a message hash with a private key
     * @param _privateKey - The private key of the signer
     * @param _messageHash - The message hash to sign
     * @return sig - The signature
     */
    function sign(uint256 _privateKey, uint256 _messageHash) internal view returns (Signature memory sig) {
        uint256 k;
        uint256 i;
        while (sig.r == 0 || sig.s == 0) {
            ++i;
            // create a pseudo-random number mod N
            k = ECBTC.mul(
                uint256(keccak256(abi.encode(_messageHash, _privateKey, block.timestamp, i))) ^ block.prevrandao, 1
            );
            if (k == 0) continue;
            // 1/k, such as 1/k * k = 1 mod N
            uint256 kInv = ECBTC.inv(k);
            // x-coordinate of k * G
            sig.r = ECBTC.mulG(k).x;
            // s = (_messageHash + r * _privateKey) / k mod N
            sig.s = ECBTC.mul(_messageHash + sig.r * _privateKey, kInv);
        }
    }

    /**
     * @notice Verifies a signature
     * @param _sig - The signature
     * @param _messageHash - The signed message hash
     * @param _publicKey - The public key of the signer
     * @return true, if the signature is valid, false otherwise
     */
    function verify(Signature calldata _sig, uint256 _messageHash, ECBTC.Point calldata _publicKey)
        internal
        pure
        returns (bool)
    {
        // 1/s, such as 1/s * s = 1 mod N
        uint256 sInv = ECBTC.inv(_sig.s);
        // u1 = _messageHash / s
        uint256 u1 = ECBTC.mul(_messageHash, sInv);
        // u2 = _sig.r / s
        uint256 u2 = ECBTC.mul(_sig.r, sInv);
        // res = u1 * G + u2 * _publicKey
        ECBTC.Point memory res = ECBTC.add(ECBTC.mulG(u1), ECBTC.mul(u2, _publicKey));
        return res.x == _sig.r;
    }
}
