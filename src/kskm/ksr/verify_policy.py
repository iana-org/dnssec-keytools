"""The checks defined in the 'Verify KSR policy parameters' section of docs/ksr-processing.md."""
import datetime
from logging import Logger

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import (AlgorithmDNSSEC, AlgorithmPolicyRSA, DEPRECATED_ALGORITHMS, SUPPORTED_ALGORITHMS)
from kskm.common.display import fmt_bundle, fmt_timedelta, fmt_timestamp
from kskm.common.ecdsa_utils import is_algorithm_ecdsa
from kskm.common.rsa_utils import is_algorithm_rsa
from kskm.common.validate import PolicyViolation
from kskm.ksr import Request

__author__ = 'ft'


class KSR_PolicyViolation(PolicyViolation):
    """A bundle in the KSR does not conform with the KSK operators policy."""

    pass


class KSR_POLICY_KEYS_Violation(KSR_PolicyViolation):
    """KSR-POLICY-KEYS policy violation."""

    pass


class KSR_POLICY_ALG_Violation(KSR_PolicyViolation):
    """KSR-POLICY-ALG policy violation."""

    pass


class KSR_POLICY_SIG_OVERLAP_Violation(KSR_PolicyViolation):
    """KSR-POLICY-SIG-OVERLAP policy violation."""

    pass


class KSR_POLICY_SIG_VALIDITY_Violation(KSR_PolicyViolation):
    """KSR-POLICY-SIG-VALIDITY policy violation."""

    pass


class KSR_POLICY_SIG_HORIZON_Violation(KSR_PolicyViolation):
    """KSR-POLICY-SIG-HORIZON policy violation."""

    pass


class KSR_POLICY_BUNDLE_INTERVAL_Violation(KSR_PolicyViolation):
    """KSR-POLICY-BUNDLE-DURATION violation."""

    pass


class KSR_POLICY_SAFETY_Violation(KSR_PolicyViolation):
    """KSR-POLICY-SAFETY violation."""

    pass


def verify_policy(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Verify that the bundles in a request are acceptable with the KSK operators configured policy."""
    logger.debug('Begin "Verify KSR policy parameters"')

    check_keys_in_bundles(request, policy, logger)
    check_zsk_policy_algorithm(request, policy, logger)
    check_bundle_overlaps(request, policy, logger)
    check_signature_validity(request, policy, logger)
    check_signature_horizon(request, policy, logger)
    check_bundle_intervals(request, policy, logger)

    logger.debug('End "Verify KSR policy parameters"')


def check_keys_in_bundles(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Check that the keys in the bundles match the KSK operator's configured policy."""
    if not policy.check_keys_match_ksk_operator_policy:
        logger.warning('KSR-POLICY-KEYS: Disabled by policy (check_keys_match_ksk_operator_policy)')
        return

    # Check the number of keys per bundle slot. The first and the last slot typically has two keys.
    if len(request.bundles) != len(policy.num_keys_per_bundle):
        raise KSR_POLICY_KEYS_Violation(f'Can\'t check number of keys per bundle for a KSR with '
                                        f'{len(request.bundles)} bundles')
    for _idx in range(len(request.bundles)):
        _bundle = request.bundles[_idx]
        if len(_bundle.keys) != policy.num_keys_per_bundle[_idx]:
            _num_keys = len(_bundle.keys)
            _expected = policy.num_keys_per_bundle[_idx]
            raise KSR_POLICY_KEYS_Violation(f'Bundle #{_idx + 1}/{_bundle.id} has {_num_keys} keys, not {_expected}')

    # Check the number of different key sets in a request.
    #
    # The standard is to have exactly three keys in the request (early,on-time,late),
    # but on some occasions a different number might be acceptable.
    # In ksr-root-2016-q3-fallback-1.xml, there were only two key sets.
    if policy.num_different_keys_in_all_bundles is not None:
        _keys = {}
        for _bundle in request.bundles:
            for _key in _bundle.keys:
                _keys[_key.key_identifier] = 1
        num_keys = len(_keys)

        if num_keys != 3:
            logger.warning('Request {} does not have three (early,on-time,late) key sets in it ({})'.format(
                request.id, num_keys
            ))
        if num_keys != policy.num_different_keys_in_all_bundles:
            raise KSR_POLICY_KEYS_Violation(f'Unacceptable number of key sets in request {request.id}, '
                                            f'({num_keys} keys instead of {policy.num_different_keys_in_all_bundles})')

    logger.info(f'KSR-POLICY-KEYS: Validated number of keys per bundle, and for all bundles')


def check_signature_validity(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Check that the signatures in a bundle match the claims in the SignaturePolicy."""
    if not policy.signature_validity_match_zsk_policy:
        logger.warning('KSR-POLICY-SIG-VALIDITY: Disabled by policy (signature_validity_match_zsk_policy)')
        return

    logger.debug('Verifying RequestBundles validity parameters:')
    num = 0
    for bundle in request.bundles:
        num += 1
        validity = bundle.expiration - bundle.inception
        logger.debug('{num:<2} {inception:29} {expiration:30} {validity}'.format(
            num=num,
            inception=fmt_timestamp(bundle.inception),
            expiration=fmt_timestamp(bundle.expiration),
            validity=validity))

    for bundle in request.bundles:
        validity = bundle.expiration - bundle.inception

        if validity < request.zsk_policy.max_signature_validity:
            _validity_str = fmt_timedelta(validity)
            _overlap_str = fmt_timedelta(request.zsk_policy.min_signature_validity)
            raise KSR_POLICY_SIG_VALIDITY_Violation(f'Bundle validity {_validity_str} < claimed '
                                                    f'min_signature_validity {_overlap_str} (in bundle {bundle.id})')

        if validity > request.zsk_policy.max_signature_validity:
            _validity_str = fmt_timedelta(validity)
            _overlap_str = fmt_timedelta(request.zsk_policy.max_signature_validity)
            raise KSR_POLICY_SIG_VALIDITY_Violation(f'Bundle validity {_validity_str} > claimed '
                                                    f'max_signature_validity {_overlap_str} (in bundle {bundle.id})')

    _num_bundles = len(request.bundles)
    _min_str = fmt_timedelta(request.zsk_policy.min_signature_validity)
    _max_str = fmt_timedelta(request.zsk_policy.max_signature_validity)
    logger.info(f'KSR-POLICY-SIG-VALIDITY: All {_num_bundles} bundles have {_min_str} <= validity >= {_max_str}')


def check_signature_horizon(request, policy, logger):
    """ Check that signatures do not expire too long into the future. """
    if not policy.signature_check_expire_horizon:
        logger.warning('KSR-POLICY-SIG-HORIZON: Disabled by policy (signature_check_expire_horizon)')
        return

    dt_now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    for bundle in request.bundles:
        expire_days = (bundle.expiration - dt_now).days
        # DPS section 5.1.4: Any RRSIG record generated as a result of a KSK signing operation will not have
        # a validity period longer than 21 days, and will never expire more than 180 days in the future.
        if policy.signature_horizon_days and expire_days > policy.signature_horizon_days:
            logger.error(f'Bundle {bundle.id} signature expires in {expire_days} days ({bundle.expiration}), '
                         f'above maximum of {policy.signature_horizon_days}')
            raise KSR_POLICY_SIG_HORIZON_Violation('Bundle signature expires too far in the future')

        # If we're checking that signatures don't expire too long into the future, it makes
        # sense to also check that they don't expire in the past which could indicate the clock
        # is wrong on the system performing the checks.
        if policy.signature_horizon_days > 0 and expire_days < 0:
            logger.error(f'Bundle {bundle.id} signature expires {abs(expire_days)} days in the past '
                         f'({bundle.expiration})')
            raise KSR_PolicyViolation('Bundle signature expire in the past')

    logger.info(f'KSR-POLICY-SIG-HORIZON: All signatures expire in less than {policy.signature_horizon_days} days')


def check_zsk_policy_algorithm(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    KSR-POLICY-ALG:
    Verify that only signature algorithms listed in the KSK operators policy
    are used in the request and that the the signature algorithms listed in
    the KSR policy have parameters allowed by the KSK operators policy.
    Parameters checked are different for different algorithms.
    """
    for alg in request.zsk_policy.algorithms:
        if alg.algorithm in DEPRECATED_ALGORITHMS:
            raise KSR_POLICY_ALG_Violation(f'Algorithm {alg.algorithm.name} deprecated')
        if alg.algorithm not in SUPPORTED_ALGORITHMS:
            raise KSR_POLICY_ALG_Violation(f'Algorithm {alg.algorithm.name} not supported')
        if is_algorithm_ecdsa(alg.algorithm) and not policy.enable_unsupported_ecdsa:
            raise KSR_POLICY_ALG_Violation('Algorithm ECDSA is not supported')

    if not policy.signature_algorithms_match_zsk_policy:
        logger.warning('KSR-POLICY-ALG: Disabled by policy (signature_algorithms_match_zsk_policy)')
        return

    _approved_algorithms = [AlgorithmDNSSEC[x] for x in policy.approved_algorithms]
    for alg in request.zsk_policy.algorithms:
        if alg.algorithm not in _approved_algorithms:
            raise KSR_POLICY_ALG_Violation(f'ZSK policy is {alg.algorithm}, but policy only allows '
                                           f'{_approved_algorithms}')

    _num_algs = len(request.zsk_policy.algorithms)

    for alg in request.zsk_policy.algorithms:
        if is_algorithm_rsa(alg.algorithm):
            # help the type checking realise that alg will be the RSA subclass
            # of AlgorithmDNSSEC (which means it has the 'exponent' field)
            assert isinstance(alg, AlgorithmPolicyRSA)

            if alg.bits not in policy.rsa_approved_key_sizes:
                raise KSR_POLICY_ALG_Violation(f'ZSK policy is RSA-{alg.bits}, but policy dictates '
                                               f'{policy.rsa_approved_key_sizes}')

            if alg.exponent not in policy.rsa_approved_exponents:
                raise KSR_POLICY_ALG_Violation(f'ZSK policy has RSA exponent {alg.exponent}, but policy dictates '
                                               f'{policy.rsa_approved_exponents}')

            logger.debug(f'ZSK policy algorithm {alg} parameters accepted')

    logger.info(f'KSR-POLICY-ALG: All {_num_algs} ZSK operator signature algorithms accepted by policy')


def check_bundle_overlaps(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that bundles are continuous and overlap according to policy.

    KSR-POLICY-SIG-OVERLAP:

      Verify that the bundles inception/expiration has an overlap period between
      _MinValidityOverlap_ and _MaxValidityOverlap_.
      This check ensures that no gaps exists in the KSR timeline.
    """
    if not policy.check_bundle_overlap:
        logger.warning('KSR-POLICY-SIG-OVERLAP: Disabled by policy (check_bundle_overlap)')
        return

    logger.debug('Verifying request {} bundle times and overlap:'.format(request.id))
    for i in range(len(request.bundles)):
        overlap_str = '-'
        previous = request.bundles[i - 1]
        this = request.bundles[i]
        if i:
            overlap = previous.expiration - this.inception
            overlap_str = fmt_timedelta(overlap)
        logger.debug('{num:<2} {id:8} {inception:19} {expiration:20} {overlap}'.format(
            num=i+1,
            id=this.id[:8],
            inception=fmt_timestamp(this.inception),
            expiration=fmt_timestamp(this.expiration),
            overlap=overlap_str))

    # check that bundles overlap, and with how much
    for i in range(1, len(request.bundles)):
        previous = request.bundles[i - 1]
        this = request.bundles[i]
        if this.inception > previous.expiration:
            raise KSR_POLICY_SIG_OVERLAP_Violation(f'Bundle "{this.id}" does not overlap with previous bundle '
                                                   f'"{previous.id}" ({this.inception} > {previous.expiration})')
        overlap = previous.expiration - this.inception
        if overlap < request.zsk_policy.min_validity_overlap:
            raise KSR_POLICY_SIG_OVERLAP_Violation('Bundle "{}" overlap {} with "{}" is < claimed minimum {}'.format(
                            fmt_bundle(this), fmt_timedelta(overlap), fmt_bundle(previous),
                            fmt_timedelta(request.zsk_policy.min_validity_overlap)
                        ))
        if overlap > request.zsk_policy.max_validity_overlap:
            raise KSR_POLICY_SIG_OVERLAP_Violation('Bundle "{}" overlap {} with "{}" is > claimed maximum {}'.format(
                            fmt_bundle(this), fmt_timedelta(overlap), fmt_bundle(previous),
                            fmt_timedelta(request.zsk_policy.max_validity_overlap),
                        ))
    logger.info(f'KSR-POLICY-SIG-OVERLAP: All bundles overlap in accordance with the stated ZSK operator policy')


def check_bundle_intervals(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that the bundles intervals fall within expected limits.

    TODO: Add this to ksr-processing.md, and update description here.
    TODO: Add test cases for this, once we have finalised the specification.
    """
    if not policy.check_bundle_intervals:
        logger.warning('KSR-POLICY-BUNDLE-INTERVALS: Disabled by policy (check_bundle_intervals)')
        return

    _min_str = fmt_timedelta(policy.min_bundle_interval)
    _max_str = fmt_timedelta(policy.max_bundle_interval)

    logger.debug(f'Verifying that bundles intervals is no less than {_min_str}, and no more than {_max_str}')
    for num in range(len(request.bundles)):
        interval = '-'
        if num:
            interval = request.bundles[num].inception - request.bundles[num - 1].inception
        logger.debug('{num:<2} {inception:29} {interval}'.format(
            num=num + 1,
            inception=fmt_timestamp(request.bundles[num].inception),
            interval=interval))

    for num in range(1, len(request.bundles)):
        interval = request.bundles[num].inception - request.bundles[num - 1].inception
        _interval_str = fmt_timedelta(interval)
        if interval < policy.min_bundle_interval:
            bundle = request.bundles[num]
            raise KSR_POLICY_BUNDLE_INTERVAL_Violation(f'Bundle #{num + 1} ({bundle.id}) interval ({_interval_str}) '
                                                       f'less than minimum acceptable interval {_min_str}')
        if interval > policy.max_bundle_interval:
            # TODO: Is it perhaps only the _last_ interval in a cycle that should be permitted to be 9 or 11 days?
            bundle = request.bundles[num]
            raise KSR_POLICY_BUNDLE_INTERVAL_Violation(f'Bundle #{num + 1} ({bundle.id}) interval ({_interval_str}) '
                                                       f'greater than maximum acceptable interval {_max_str}')

    logger.info(f'KSR-POLICY-BUNDLE-INTERVALS: All bundles intervals in accordance with the KSK operator policy')
