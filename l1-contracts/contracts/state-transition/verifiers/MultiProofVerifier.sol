// SPDX-License-Identifier: MIT

pragma solidity 0.8.28;

import {IVerifier} from "../chain-interfaces/IVerifier.sol";
import {IZiskVerifier} from "../chain-interfaces/IZiskVerifier.sol";
import {Ownable2Step} from "@openzeppelin/contracts-v4/access/Ownable2Step.sol";

/// @title Multi-Proof Verifier
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice Requires BOTH an Airbender proof and a ZiSK proof for each state transition.
///         Only accepts the combined proof type (MULTI_PROOF_TYPE = 5).
///         Single-system proofs (type 2) and mock proofs (type 3) are rejected.
///
/// @dev Proof encoding received from the Executor:
///      proof[0] = proof_type | (verifier_version << 8)
///      proof[1] = previous_hash (used by computeZKsyncOSHash)
///
///      For type 5 (MULTI_PROOF):
///      proof[2]              = N  (number of Airbender proof elements)
///      proof[3 .. 3+N]       = Airbender SNARK proof elements
///      proof[3+N .. 3+N+24]  = ZiSK SNARK proof (24 uint256 = 768 bytes)
///      proof[3+N+24 .. 3+N+34] = ZiSK public values (10 uint256 = 320 bytes):
///        word 0     = programVK (guest-ELF ROM root)
///        words 1..8 = guest publics (ziskos's full 256-byte output region)
///        word 9     = vadcop-final VK (rootCVadcopFinal)
///
///      The ZiSK section comes in two shapes, selected by the batch-range
///      size (the length of `_publicInputs`):
///      - Single batch: a per-batch STF proof. Word 0 is the STF guest's
///        programVK and word 1 the full 32-byte batch commitment
///        keccak256(prevState || newState || batchInfo).
///      - Range (N > 1 batches): ONE aggregated proof for the whole range.
///        The aggregator guest verified one STF proof per batch, so word 0
///        is the AGGREGATOR guest's programVK and word 1 the binding digest
///        keccak256(innerProgramVK || rootCVadcopFinal || chainedPI) over
///        everything the inner proofs attested to.
contract MultiProofVerifier is Ownable2Step, IVerifier {
    uint256 internal constant MULTI_PROOF_TYPE = 5;

    /// @notice Inner verifier for Airbender proofs (implements IVerifier).
    IVerifier public airbenderVerifier;
    /// @notice Inner verifier for per-batch ZiSK proofs. Must implement
    ///         IZiskVerifier: range mode reads its pinned wire-form VKs to
    ///         recompute the aggregated proof's binding digest.
    IVerifier public ziskVerifier;
    /// @notice Inner verifier for aggregated (multi-batch range) ZiSK proofs.
    ///         Pins the AGGREGATOR guest's programVK. While unset, range
    ///         proofs are rejected (single-batch proofs are unaffected).
    IVerifier public ziskRangeVerifier;

    error EmptyProof();
    error UnknownProofType(uint256 proofType);
    error ProofTooShort();
    error AirbenderVerificationFailed();
    error ZiskVerificationFailed();
    error ZiskCommitmentMismatch(uint256 expected, uint256 got);
    error ZiskRangeDigestMismatch(uint256 expected, uint256 got);
    error ZiskRangeVerifierNotSet();

    constructor(
        IVerifier _airbenderVerifier,
        IVerifier _ziskVerifier,
        address _initialOwner
    ) {
        airbenderVerifier = _airbenderVerifier;
        ziskVerifier = _ziskVerifier;
        _transferOwnership(_initialOwner);
    }

    /// @notice Update the Airbender verifier.
    function setAirbenderVerifier(IVerifier _verifier) external onlyOwner {
        airbenderVerifier = _verifier;
    }

    /// @notice Update the ZiSK verifier.
    function setZiskVerifier(IVerifier _verifier) external onlyOwner {
        ziskVerifier = _verifier;
    }

    /// @notice Update the ZiSK range (aggregated-proof) verifier.
    function setZiskRangeVerifier(IVerifier _verifier) external onlyOwner {
        ziskRangeVerifier = _verifier;
    }

    /// @notice Verify a combined Airbender + ZiSK proof.
    function verify(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof
    ) public view virtual override returns (bool) {
        if (_proof.length == 0) revert EmptyProof();

        uint256 proofType = _proof[0] & 255;

        if (proofType == MULTI_PROOF_TYPE) {
            return _verifyMultiProof(_publicInputs, _proof);
        }

        revert UnknownProofType(proofType);
    }

    /// @inheritdoc IVerifier
    function verificationKeyHash() external view override returns (bytes32) {
        return airbenderVerifier.verificationKeyHash();
    }

    /// @dev Verify a multi-proof containing both Airbender and ZiSK sub-proofs.
    function _verifyMultiProof(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof
    ) internal view returns (bool) {
        // proof[0] = type | version, proof[1] = previous_hash, proof[2] = N
        if (_proof.length < 3) revert ProofTooShort();

        uint256 airbenderLen = _proof[2];
        // 34 = 24 proof words + 10 public-values words (320 bytes).
        if (_proof.length < 3 + airbenderLen + 34) revert ProofTooShort();

        uint256[] memory args = new uint256[](1);
        args[0] = _computeZKsyncOSHash(_proof[1], _publicInputs);

        // --- Airbender verification ---
        uint256[] memory airbenderProof = new uint256[](airbenderLen);
        for (uint256 i = 0; i < airbenderLen; i++) {
            airbenderProof[i] = _proof[3 + i];
        }
        if (!airbenderVerifier.verify(args, airbenderProof)) {
            revert AirbenderVerificationFailed();
        }

        // --- Cross-proof binding ---
        // The ZiSK public values embed what the proof attests to
        // (public-values word 1, right after the programVK word). Requiring
        // it to match the batch range verified above binds both sub-proofs
        // to one state transition — without it they could attest to
        // different transitions.
        uint256 ziskStart = 3 + airbenderLen;
        IVerifier ziskProofVerifier;
        if (_publicInputs.length == 1) {
            // Single batch: word 1 is the full 32-byte batch commitment; the
            // batch public input is that same commitment truncated by 32 bits.
            ziskProofVerifier = ziskVerifier;
            uint256 ziskCommitment = _proof[ziskStart + 25];
            if (ziskCommitment >> 32 != args[0]) {
                revert ZiskCommitmentMismatch(args[0], ziskCommitment >> 32);
            }
        } else {
            // Range (N > 1 batches): the ZiSK proof is one AGGREGATED proof —
            // the aggregator guest verified one inner (STF) proof per batch
            // and committed a single digest over everything they attested to:
            //   keccak256(innerProgramVK || rootCVadcopFinal || chainedPI)
            // with the inner wire-form pins read back from the registered
            // per-batch verifier, and chainedPI the SELF-CONTAINED batch
            // chain: _computeZKsyncOSHash seeded with 0, never with
            // previous_hash. An aggregated range always opens its own chain,
            // even when the Airbender public input above continues a nonzero
            // previous_hash. The aggregated proof itself is checked below by
            // ziskRangeVerifier, which pins the AGGREGATOR guest's programVK.
            ziskProofVerifier = ziskRangeVerifier;
            if (address(ziskProofVerifier) == address(0)) {
                revert ZiskRangeVerifierNotSet();
            }
            uint256 expectedDigest = uint256(
                keccak256(
                    abi.encodePacked(
                        IZiskVerifier(address(ziskVerifier)).programVK(),
                        IZiskVerifier(address(ziskVerifier)).rootCVadcopFinal(),
                        bytes32(_computeZKsyncOSHash(0, _publicInputs))
                    )
                )
            );
            uint256 ziskDigest = _proof[ziskStart + 25];
            if (ziskDigest != expectedDigest) {
                revert ZiskRangeDigestMismatch(expectedDigest, ziskDigest);
            }
        }

        // --- ZiSK verification ---
        uint256[] memory ziskProof = new uint256[](34);
        for (uint256 i = 0; i < 34; i++) {
            ziskProof[i] = _proof[ziskStart + i];
        }
        if (!ziskProofVerifier.verify(args, ziskProof)) {
            revert ZiskVerificationFailed();
        }

        return true;
    }

    /// @dev Compute the ZKsync OS hash: chain public inputs with keccak256 truncated to 224 bits.
    function _computeZKsyncOSHash(
        uint256 initialHash,
        uint256[] calldata _publicInputs
    ) internal pure returns (uint256 result) {
        result = initialHash;
        uint256 i = 0;
        if (result == 0) {
            result = _publicInputs[0];
            i = 1;
        }
        for (; i < _publicInputs.length; ++i) {
            result = uint256(keccak256(abi.encodePacked(result, _publicInputs[i]))) >> 32;
        }
    }
}
