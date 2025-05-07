// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECBTC} from "./ECBTC.sol";
import {SerialLib} from "./SerialLib.sol";
import {Point, Signature} from "./Structs.sol";

/**
 * @title SigLib - Signature Library
 * @notice Takes care of signing and verifying signatures.
 * @author https://github.com/nzmpi
 */
library SigLib {
    using ECBTC for *;
    using SerialLib for *;

    /**
     * Signs a message hash with a private key
     * @param _messageHash - The message hash to sign
     * @param _privateKey - The private key of the signer
     * @return sig - The signature
     */
    function sign(uint256 _messageHash, uint256 _privateKey) internal view returns (Signature memory sig) {
        uint256 k;
        uint256 i;
        while (sig.r == 0 || sig.s == 0) {
            ++i;
            // create a pseudo-random number mod N
            k = (uint256(keccak256(abi.encode(_messageHash, _privateKey, block.timestamp, i))) ^ block.prevrandao).mod();
            if (k == 0) continue;
            // x-coordinate of k * G
            sig.r = k.mulG().x;
            // s = (_messageHash + r * _privateKey) / k mod N
            sig.s = (_messageHash.add(sig.r.mul(_privateKey))).mul(k.inv());
        }
    }

    /**
     * Verifies a signature
     * @param _messageHash - The message hash that was signed
     * @param _sig - The signature
     * @param _publicKey - The public key of the signer
     * @return true, if the signature is valid, false otherwise
     */
    function verify(uint256 _messageHash, Signature memory _sig, Point memory _publicKey)
        internal
        pure
        returns (bool)
    {
        // 1/s, such as 1/s * s = 1 mod N
        uint256 sInv = _sig.s.inv();
        // u1 = _messageHash / s
        uint256 u1 = _messageHash.mul(sInv);
        // u2 = _sig.r / s
        uint256 u2 = _sig.r.mul(sInv);
        // res = u1 * G + u2 * _publicKey
        Point memory res = u1.mulG().add(u2.mul(_publicKey));
        return res.x == _sig.r;
    }

    /**
     * Verifies a signature
     * @param _messageHash - The message hash that was signed
     * @param _sig - The signature
     * @param _publicKey - The public key of the signer
     * @return true, if the signature is valid, false otherwise
     */
    function verify(uint256 _messageHash, bytes memory _sig, bytes memory _publicKey) internal pure returns (bool) {
        return verify(_messageHash, _sig.parseSignature(), _publicKey.parsePublicKey());
    }
}
