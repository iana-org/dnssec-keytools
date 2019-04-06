"""The checks defined in the 'Verify KSR bundles' section of docs/ksr-processing.md."""
from logging import Logger
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature

from kskm.common.data import AlgorithmPolicy, AlgorithmPolicyRSA, Key
from kskm.common.dnssec import calculate_key_tag
from kskm.common.rsa_utils import (RSAPublicKeyData, decode_rsa_public_key,
                                   is_algorithm_rsa)
from kskm.common.signature import validate_signatures
from kskm.common.validate import PolicyViolation, fail
from kskm.ksr import Request
from kskm.ksr.policy import RequestPolicy


class KSR_BundleViolation(PolicyViolation):
    """Policy violation in a KSRs bundles."""

    pass


class KSR_BUNDLE_KEYS_Violation(KSR_BundleViolation):
    """KSR-BUNDLE-KEYS policy violation."""

    pass


class KSR_BUNDLE_POP_Violation(KSR_BundleViolation):
    """KSR-BUNDLE-POP (Proof of Possession) policy violation."""

    pass


class KSR_BUNDLE_UNIQUE_Violation(KSR_BundleViolation):
    """KSR-BUNDLE-UNIQUE violation."""

    pass


def verify_bundles(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Verify that the bundles in a request conform with the ZSK operators stated policy."""
    logger.debug('Begin "Verify KSR bundles"')
    if policy.num_bundles is not None and len(request.bundles) != policy.num_bundles:
        # TODO: This check is not part of the specification
        _num_bundles = len(request.bundles)
        fail(policy, KSR_BundleViolation,
             f'Wrong number of bundles in request ({_num_bundles}, expected {policy.num_bundles})')
    #
    # Checks according to the specification below this point:
    #

    check_unique_ids(request, policy, logger)
    check_keys_match_zsk_policy(request, policy, logger)
    check_proof_of_possession(request, policy, logger)

    logger.debug('End "Verify KSR bundles"')


def check_unique_ids(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Verify that all requested bundles has unique IDs.

    KSR-BUNDLE-UNIQUE:
      Verify that all requested bundles has unique IDs

    NOTE: This is seen as a fundamental requirement to be able to correctly refer to bundles in logs etc.
          As such, there is no policy option to disable this check.

    """
    # TODO: Interpreted as 'unique in this request', not in all requests ever processed
    seen: Dict[str, int] = {}
    for bundle in request.bundles:
        if bundle.id in seen:
            fail(policy, KSR_BUNDLE_UNIQUE_Violation,
                 f'More than one bundle with id {bundle.id}')
        seen[bundle.id] = 1

    _num_bundles = len(request.bundles)
    logger.info(f'KSR-BUNDLE-UNIQUE: All {_num_bundles} bundles have unique ids')
    return


def check_keys_match_zsk_policy(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that the keys of a bundle match the claims in the SignaturePolicy.

    KSR-BUNDLE-KEYS:
      Verify that the keys are consistent (key id, tag, public key parameters etc.)
      across all bundles and that the key tags are correctly calculated.
    """
    # TODO: Not all implemented - need clarification of specification
    if not policy.keys_match_zsk_policy:
        logger.info('KSR-BUNDLE-KEYS: Disabled by policy (keys_match_zsk_policy)')
        return

    seen: Dict[int, Key] = {}

    for bundle in request.bundles:
        for key in bundle.keys:
            if key.key_tag in seen:
                # verify the key is identical to previous time it was found
                if key == seen[key.key_tag]:
                    continue
                logger.debug(f'Key as seen before : {seen[key.key_tag]}')
                logger.debug(f'Key in bundle {bundle.id}: {key}')
                fail(policy, KSR_BUNDLE_KEYS_Violation,
                     f'Key tag {key.key_tag} matches two different keys (the second one in bundle {bundle.id})')

            if is_algorithm_rsa(key.algorithm):
                pubkey = decode_rsa_public_key(key.public_key)

                _matching_alg = _find_matching_zsk_policy_rsa_alg(request, key, pubkey, ignore_exponent=False)
                if not _matching_alg and not policy.rsa_exponent_match_zsk_policy:
                    # No match was found. A common error in historic KSRs is to have mismatching exponent
                    # in ZSK policy and actual key, so if the policy allows it we will search again and
                    # this time ignore the exponent.
                    _matching_alg = _find_matching_zsk_policy_rsa_alg(request, key, pubkey, ignore_exponent=True)
                    if _matching_alg:
                        logger.warning(f'KSR-BUNDLE-KEYS: Key {key.key_identifier} in bundle {bundle.id} has '
                                       f'exponent {pubkey.exponent}, not matching the ZSK SignaturePolicy')
                if not _matching_alg:
                    fail(policy, KSR_BUNDLE_KEYS_Violation,
                         f'Key {key.key_identifier} in bundle {bundle.id} does not match the ZSK SignaturePolicy')
                else:
                    logger.debug(f'Key {key.key_tag}/{key.key_identifier} parameters accepted')
                    seen[key.key_tag] = key
            else:
                # TODO: Not exactly a policy violation as much as maybe a contract violation
                fail(policy, PolicyViolation,
                     f'Key {key.key_identifier} in bundle {bundle.id} uses unhandled algorithm: {key.algorithm}')

            _key_tag = calculate_key_tag(key)
            if _key_tag != key.key_tag:
                fail(policy, KSR_BUNDLE_KEYS_Violation,
                     f'Key {key.key_identifier} in bundle {bundle.id} has key tag {key.key_tag}, should be {_key_tag}')

    _num_keys = len(seen)
    logger.info(f'KSR-BUNDLE-KEYS: All {_num_keys} unique keys in the bundles accepted by policy')


def _find_matching_zsk_policy_rsa_alg(request: Request, key: Key, pubkey: RSAPublicKeyData,
                                      ignore_exponent: bool = False) -> Optional[AlgorithmPolicy]:
    for this in request.zsk_policy.algorithms:
        if not isinstance(this, AlgorithmPolicyRSA):
            continue
        if key.algorithm == this.algorithm and pubkey.bits == this.bits and pubkey.exponent == this.exponent:
            return this
        if key.algorithm == this.algorithm and pubkey.bits == this.bits and ignore_exponent:
            return this
    return None


def check_proof_of_possession(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Validate requester proof of ownership of all the keys in the bundles.

    KSR-BUNDLE-POP:
      For each key bundle in KSR(n), verify the signature by each ZSK to confirm proof-of-possession
      of private component of each ZSK.
      The inception and expiration times of the RRSIGs in the KSR are ignored when checking proof-of-possession.
    """
    if not policy.validate_signatures:
        logger.info('KSR-BUNDLE-POP: Disabled by policy (validate_signatures)')
        return
    for bundle in request.bundles:
        try:
            if not validate_signatures(bundle):
                fail(policy, KSR_BUNDLE_POP_Violation,
                     f'Unknown signature validation result in bundle {bundle.id}')
        except InvalidSignature:
            fail(policy, KSR_BUNDLE_POP_Violation,
                 f'Invalid signature encountered in bundle {bundle.id}')
    _num_bundles = len(request.bundles)
    logger.info(f'KSR-BUNDLE-POP: All {_num_bundles} bundles contain proof-of-possession')
