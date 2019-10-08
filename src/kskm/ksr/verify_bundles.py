"""The checks defined in the 'Verify KSR bundles' section of docs/ksr-processing.md."""
from logging import Logger
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmPolicy, AlgorithmPolicyRSA, Key, FlagsDNSKEY
from kskm.common.dnssec import calculate_key_tag
from kskm.common.rsa_utils import (KSKM_PublicKey_RSA, decode_rsa_public_key,
                                   is_algorithm_rsa)
from kskm.common.signature import validate_signatures
from kskm.common.validate import PolicyViolation
from kskm.ksr import Request

__author__ = 'ft'


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


class KSR_BUNDLE_COUNT_Violation(KSR_BundleViolation):
    """KSR-BUNDLE-COUNT violation."""

    pass


def verify_bundles(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Verify that the bundles in a request conform with the ZSK operators stated policy."""
    logger.debug('Begin "Verify KSR bundles"')

    check_unique_ids(request, policy, logger)
    check_keys_match_zsk_policy(request, policy, logger)
    check_proof_of_possession(request, policy, logger)
    check_bundle_count(request, policy, logger)

    logger.debug('End "Verify KSR bundles"')


def check_unique_ids(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Verify that all requested bundles has unique IDs.

    KSR-BUNDLE-UNIQUE:
      Verify that all requested bundles has unique IDs

    NOTE: This is seen as a fundamental requirement to be able to correctly refer to bundles in logs etc.
          As such, there is no policy option to disable this check.

    NOTE: This only verifies that bundle IDs are not re-used within this request. Later when the last
          SKR is loaded, another pass will be made to validate that no bundle ID from this request was
          present in the last SKR.
    """
    seen: Dict[str, int] = {}
    for bundle in request.bundles:
        if bundle.id in seen:
            raise KSR_BUNDLE_UNIQUE_Violation(f'More than one bundle with id {bundle.id}')
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
    if not policy.keys_match_zsk_policy:
        logger.warning('KSR-BUNDLE-KEYS: Disabled by policy (keys_match_zsk_policy)')
        return

    seen: Dict[str, Key] = {}

    for bundle in request.bundles:
        for key in bundle.keys:
            if key.key_identifier in seen:
                # verify the key is identical to previous time it was found
                if key == seen[key.key_identifier]:
                    # We've seen and checked this exact key before, no need to do it again
                    continue
                logger.debug(f'Key as seen before : {seen[key.key_identifier]}')
                logger.debug(f'Key in bundle {bundle.id}: {key}')
                raise KSR_BUNDLE_KEYS_Violation(f'Key tag {key.key_identifier} matches two different keys '
                                                f'(the second one in bundle {bundle.id})')

            # This is a new key - perform more checks on it
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
                    raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                    f'does not match the ZSK SignaturePolicy')
                else:
                    logger.debug(f'Key {key.key_tag}/{key.key_identifier} parameters accepted')
                    seen[key.key_identifier] = key
            else:
                raise ValueError(f'Key {key.key_identifier} in bundle {bundle.id} uses unhandled algorithm: '
                                 f'{key.algorithm}')

            ACCEPTABLE_ZSK_FLAGS = FlagsDNSKEY.ZONE.value
            if key.flags != ACCEPTABLE_ZSK_FLAGS:
                raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                f'has flags {key.flags}, only {ACCEPTABLE_ZSK_FLAGS} acceptable')
            else:
                logger.debug(f'Key {key.key_tag}/{key.key_identifier} flags accepted')

            _key_tag = calculate_key_tag(key)
            if _key_tag != key.key_tag:
                raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                f'has key tag {key.key_tag}, should be {_key_tag}')

    _num_keys = len(seen)
    logger.info(f'KSR-BUNDLE-KEYS: All {_num_keys} unique keys in the bundles accepted by policy')


def _find_matching_zsk_policy_rsa_alg(request: Request, key: Key, pubkey: KSKM_PublicKey_RSA,
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
        logger.warning('KSR-BUNDLE-POP: Disabled by policy (validate_signatures)')
        return
    for bundle in request.bundles:
        try:
            if not validate_signatures(bundle):
                raise KSR_BUNDLE_POP_Violation(f'Unknown signature validation result in bundle {bundle.id}')
        except InvalidSignature:
            raise KSR_BUNDLE_POP_Violation(f'Invalid signature encountered in bundle {bundle.id}')
    _num_bundles = len(request.bundles)
    logger.info(f'KSR-BUNDLE-POP: All {_num_bundles} bundles contain proof-of-possession')


def check_bundle_count(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Validate the number of bundles in the request.

    KSR-BUNDLE-COUNT:
      Verify that the number of requested bundles are within acceptable limits.
    """
    if policy.num_bundles is not None and len(request.bundles) != policy.num_bundles:
        _num_bundles = len(request.bundles)
        raise KSR_BUNDLE_COUNT_Violation(f'Wrong number of bundles in request ({_num_bundles}, '
                                         f'expected {policy.num_bundles})')
