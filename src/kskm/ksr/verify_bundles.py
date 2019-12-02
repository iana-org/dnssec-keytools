"""The checks defined in the 'Verify KSR bundles' section of docs/ksr-processing.md."""
from datetime import timedelta, datetime
from logging import Logger
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmPolicy, AlgorithmPolicyRSA, FlagsDNSKEY, Key, AlgorithmPolicyECDSA
from kskm.common.dnssec import calculate_key_tag
from kskm.common.ecdsa_utils import is_algorithm_ecdsa
from kskm.common.rsa_utils import (KSKM_PublicKey_RSA, decode_rsa_public_key,
                                   is_algorithm_rsa)
from kskm.common.signature import validate_signatures
from kskm.common.validate import PolicyViolation
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle

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


class KSR_BUNDLE_CYCLE_DURATION_Violation(KSR_BundleViolation):
    """KSR-BUNDLE-CYCLE violation."""

    pass


def verify_bundles(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Verify that the bundles in a request conform with the ZSK operators stated policy."""
    logger.debug('Begin "Verify KSR bundles"')

    check_unique_ids(request, policy, logger)
    check_keys_match_zsk_policy(request, policy, logger)
    check_proof_of_possession(request, policy, logger)
    check_bundle_count(request, policy, logger)
    check_cycle_durations(request, policy, logger)

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
                logger.debug(f'Key {key.key_tag}/{key.key_identifier} parameters accepted')
                seen[key.key_identifier] = key
            elif is_algorithm_ecdsa(key.algorithm):
                logger.warning(f'Key {key.key_identifier} in bundle {bundle.id} is an ECDSA key - this is untested')
                if not _find_matching_zsk_policy_ecdsa_alg(request):
                    raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                    f'does not match the ZSK SignaturePolicy')
                logger.debug(f'Key {key.key_tag}/{key.key_identifier} parameters accepted')
                seen[key.key_identifier] = key
            else:
                raise ValueError(f'Key {key.key_identifier} in bundle {bundle.id} uses unhandled algorithm: '
                                 f'{key.algorithm}')

            ACCEPTABLE_ZSK_FLAGS = FlagsDNSKEY.ZONE.value
            if key.flags != ACCEPTABLE_ZSK_FLAGS:
                raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                f'has flags {key.flags}, only {ACCEPTABLE_ZSK_FLAGS} acceptable')
            logger.debug(f'Key {key.key_tag}/{key.key_identifier} flags accepted')

            _key_tag = calculate_key_tag(key)
            if _key_tag != key.key_tag:
                raise KSR_BUNDLE_KEYS_Violation(f'Key {key.key_identifier} in bundle {bundle.id} '
                                                f'has key tag {key.key_tag}, should be {_key_tag}')
            logger.debug(f'Key {key.key_tag}/{key.key_identifier} keytag accepted')

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


def _find_matching_zsk_policy_ecdsa_alg(request: Request) -> Optional[AlgorithmPolicy]:
    for this in request.zsk_policy.algorithms:
        if isinstance(this, AlgorithmPolicyECDSA):
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

        # All signatures in the bundle have been confirmed to sign all keys in the bundle.
        # Now verify that all keys in the bundle actually was used to create a signature.
        for _key in bundle.keys:
            _sigs = [x for x in bundle.signatures if x.key_identifier == _key.key_identifier]
            if not _sigs:
                raise KSR_BUNDLE_POP_Violation(f'Key {_key} was not used to sign the keys in bundle {bundle.id}')

    _num_bundles = len(request.bundles)
    logger.info(f'KSR-BUNDLE-POP: All {_num_bundles} bundles contain proof-of-possession')


def check_bundle_count(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Validate the number of bundles in the request.

    KSR-BUNDLE-COUNT:
      Verify that the number of requested bundles are within acceptable limits.
    """
    _num_bundles = len(request.bundles)
    if policy.num_bundles is not None and _num_bundles != policy.num_bundles:
        raise KSR_BUNDLE_COUNT_Violation(f'Wrong number of bundles in request ({_num_bundles}, '
                                         f'expected {policy.num_bundles})')
    logger.info(f'KSR-BUNDLE-COUNT: Number of bundles ({_num_bundles}) accepted')


def check_cycle_durations(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that the whole cycles length fall within expected limits.

    TODO: Add this to ksr-processing.md, and update description here.
    TODO: Add test cases for this, once we have finalised the specification.
    """
    if not policy.check_cycle_length:
        logger.warning('KSR-BUNDLE-CYCLE-DURATION: Disabled by policy (check_cycle_length)')
        return

    if not request.bundles:
        logger.warning('KSR-BUNDLE-CYCLE-DURATION: No bundles - can\'t check anything')
        return

    _min_str = _fmt_timedelta(policy.min_bundle_interval)
    _max_str = _fmt_timedelta(policy.max_bundle_interval)

    logger.debug(f'Verifying that all bundles are between {_min_str} and {_max_str} apart')
    for idx in range(1, len(request.bundles)):
        bundle = request.bundles[idx]
        prev_bundle = request.bundles[idx - 1]
        interval = bundle.inception - prev_bundle.inception
        _interval_str = _fmt_timedelta(interval)
        if interval < policy.min_bundle_interval:
            raise KSR_BUNDLE_CYCLE_DURATION_Violation(f'Bundle #{idx} ({bundle.id}) '
                                                      f'interval {_interval_str} < minimum {_min_str}')
        if interval > policy.max_bundle_interval:
            raise KSR_BUNDLE_CYCLE_DURATION_Violation(f'Bundle #{idx} ({bundle.id}) '
                                                      f'interval {_interval_str} > maximum {_max_str}')

    cycle_inception_length = request.bundles[-1].inception - request.bundles[0].inception
    _inc_len_str = _fmt_timedelta(cycle_inception_length)
    _min_inc_str = _fmt_timedelta(policy.min_cycle_inception_length)
    _max_inc_str = _fmt_timedelta(policy.max_cycle_inception_length)

    logger.debug(f'Verifying that first bundle inception to last bundle inception ({_inc_len_str}) '
                 f'is between {_min_inc_str} and {_max_inc_str}')

    if cycle_inception_length < policy.min_cycle_inception_length:
        raise KSR_BUNDLE_CYCLE_DURATION_Violation(f'Cycle inception length ({_inc_len_str}) '
                                                  f'less than minimum acceptable length {_min_inc_str}')
    if cycle_inception_length > policy.max_cycle_inception_length:
        raise KSR_BUNDLE_CYCLE_DURATION_Violation(f'Cycle length ({_inc_len_str}) '
                                                  f'greater than maximum acceptable length {_max_str}')

    logger.info(f'KSR-BUNDLE-CYCLE-DURATION: The cycles length is in accordance with the KSK operator policy')


def _fmt_timedelta(tdelta: timedelta) -> str:
    res = str(tdelta)
    if res.endswith('days, 0:00:00') or res.endswith('day, 0:00:00'):
        # cut off the unnecessary 0:00:00 after "days"
        res = res[:0 - len(', 0:00:00')]
    return res


def _fmt_timestamp(ts: datetime) -> str:
    return ts.isoformat().split('+')[0]
