""" The checks defined in the 'Verify KSR policy parameters' section of docs/ksr-processing.md. """
from logging import Logger

from datetime import timedelta

from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.ksr.policy import RequestPolicy
from kskm.common.validate import PolicyViolation, fail
from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyRSA
from kskm.common.rsa_utils import is_algorithm_rsa


class KSR_PolicyViolation(PolicyViolation):
    pass


class SignaturePolicyViolation(KSR_PolicyViolation):
    pass


class KSR_POLICY_KEYS_Violation(KSR_PolicyViolation):
    pass


class KSR_POLICY_ALG_Violation(KSR_PolicyViolation):
    pass


class KSR_POLICY_PARAMS_Violation(KSR_PolicyViolation):
    pass


class KSR_POLICY_SIG_OVERLAP_Violation(KSR_PolicyViolation):
    pass


class KSR_POLICY_SIG_VALIDITY_Violation(KSR_PolicyViolation):
    pass


def verify_policy(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    logger.debug('Begin "Verify KSR policy parameters"')

    check_keys_in_bundles(request, policy, logger)
    check_zsk_policy_signature_algorithms(request, policy, logger)
    check_zsk_policy_signature_parameters(request, policy, logger)
    check_bundle_overlaps(request, policy, logger)
    check_signature_validity(request, policy, logger)

    # TODO: This check isn't part of the specification
    if policy.num_bundles is not None and len(request.bundles) != policy.num_bundles:
        fail(policy, KSR_PolicyViolation, 'Wrong number of bundles in request ({}, expected {})'.format(
            len(request.bundles), policy.num_bundles))

    logger.debug('End "Verify KSR policy parameters"')


def check_keys_in_bundles(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Check that the keys in the bundles match the KSK operator's configured policy."""
    if not policy.check_keys_match_ksk_operator_policy:
        logger.warning('KSR-POLICY-KEYS: Disabled by policy (check_keys_match_ksk_operator_policy)')
        return

    # Check the number of different key sets in a request.
    #
    # The standard is to have exactly three keys in the request (early,on-time,late),
    # but on some occasions a different number might be acceptable.
    # In ksr-root-2016-q3-fallback-1.xml, there were only two key sets.
    if policy.acceptable_key_set_lengths is not None:
        keytags = {}
        for _bundle in request.bundles:
            for _key in _bundle.keys:
                keytags[_key.key_tag] = 1
        num_keys = len(keytags)

        if num_keys != 3:
            logger.warning('Request {} does not have three (early,on-time,late) key sets in it ({})'.format(
                request.id, num_keys
            ))
        if num_keys in policy.acceptable_key_set_lengths:
            return
        fail(policy, KSR_POLICY_KEYS_Violation,
             f'Unacceptable number of key sets in request {request.id} '
             f'({num_keys} not one of {policy.acceptable_key_set_lengths})')


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
            inception=bundle.inception.isoformat().split('+')[0],
            expiration=bundle.expiration.isoformat().split('+')[0],
            validity=validity))

    for bundle in request.bundles:
        validity = bundle.expiration - bundle.inception

        if validity < request.zsk_policy.max_signature_validity:
            _validity_str = _fmt_timedelta(validity)
            _overlap_str = _fmt_timedelta(request.zsk_policy.min_signature_validity)
            return fail(policy, KSR_POLICY_SIG_VALIDITY_Violation,
                        f'Bundle validity {_validity_str} < claimed min_signature_validity {_overlap_str} '
                        f'(in bundle {bundle.id})')

        if validity > request.zsk_policy.max_signature_validity:
            _validity_str = _fmt_timedelta(validity)
            _overlap_str = _fmt_timedelta(request.zsk_policy.max_signature_validity)
            return fail(policy, KSR_POLICY_SIG_VALIDITY_Violation,
                        f'Bundle validity {_validity_str} > claimed max_signature_validity {_overlap_str} '
                        f'(in bundle {bundle.id})')

    _num_bundles = len(request.bundles)
    _min_str = _fmt_timedelta(request.zsk_policy.min_signature_validity)
    _max_str = _fmt_timedelta(request.zsk_policy.max_signature_validity)
    logger.info(f'KSR-POLICY-SIG-VALIDITY: All {_num_bundles} bundles have {_min_str} <= validity >= {_max_str}')


def check_zsk_policy_signature_algorithms(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that the key parameters in the ZSK operators policy are accepted by KSK operator policy.

    KSR-POLICY-ALG:
    Verify that only signature algorithms listed in the policy are used in the bundle.
    """
    # TODO: Not all implemented - need clarification of specification
    if not policy.signature_algorithms_match_zsk_policy:
        logger.warning('KSR-POLICY-ALG: Disabled by policy (signature_algorithms_match_zsk_policy)')
        return

    _approved_algorithms = [AlgorithmDNSSEC[x] for x in policy.approved_algorithms]
    for alg in request.zsk_policy.algorithms:
        if alg.algorithm not in _approved_algorithms:
            fail(policy, KSR_POLICY_ALG_Violation,
                 f'ZSK policy is {alg.algorithm}, but policy only allows {_approved_algorithms}')

    _num_algs = len(request.zsk_policy.algorithms)
    logger.info(f'KSR-POLICY-ALG: All {_num_algs} ZSK operator signature algorithms accepted by policy')

def check_zsk_policy_signature_parameters(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check that the key parameters in the ZSK operators policy are accepted by KSK operator policy.

    KSR-POLICY-PARAMS:
    Verify that the signature algorithms listed in the KSR policy have parameters allowed
    by the KSK operators policy. Parameters checked are different for different algorithms.

      RSA:
        - key size
        - exponent
    """
    count = 0
    for alg in request.zsk_policy.algorithms:
        if is_algorithm_rsa(alg.algorithm):
            # help the type checking realise that alg will be the RSA subclass of
            # AlgorithmDNSSEC (which means it has the 'exponent' field)
            assert isinstance(alg, AlgorithmPolicyRSA)

            count += 1
            validated = True
            if alg.bits not in policy.rsa_approved_key_sizes:
                validated = False
                fail(policy, KSR_POLICY_PARAMS_Violation,
                     f'ZSK policy is RSA-{alg.bits}, but policy dictates {policy.rsa_approved_key_sizes}')

            if alg.exponent not in policy.rsa_approved_exponents:
                validated = False
                fail(policy, KSR_POLICY_PARAMS_Violation,
                     f'ZSK policy has RSA exponent {alg.exponent}, but policy dictates '
                     f'{policy.rsa_approved_exponents}')

            if validated:
                logger.debug(f'ZSK policy algorithm {alg} parameters accepted')

    logger.info(f'KSR-POLICY-PARAMS: {count} signature algorithms parameters accepted by policy')



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
            overlap_str = _fmt_timedelta(overlap)
        logger.debug('{num:<2} {id:8} {inception:19} {expiration:20} {overlap}'.format(
            num=i+1,
            id=this.id[:8],
            inception=this.inception.isoformat().split('+')[0],
            expiration=this.expiration.isoformat().split('+')[0],
            overlap=overlap_str))

    # check that bundles overlap, and with how much
    for i in range(1, len(request.bundles)):
        previous = request.bundles[i - 1]
        this = request.bundles[i]
        if this.inception > previous.expiration:
            return fail(policy, KSR_POLICY_SIG_OVERLAP_Violation,
                        'Bundle "{}" does not overlap with previous bundle "{}"'.format(this, previous)
                        )
        overlap = previous.expiration - this.inception
        if overlap < request.zsk_policy.min_validity_overlap:
            return fail(policy, KSR_POLICY_SIG_OVERLAP_Violation,
                        'Bundle "{}" overlap {} with "{}" is < claimed minimum {}'.format(
                            _fmt_bundle(this), _fmt_timedelta(overlap), _fmt_bundle(previous),
                            _fmt_timedelta(request.zsk_policy.min_validity_overlap)
                        ))
        overlap = previous.expiration - this.inception
        if overlap > request.zsk_policy.max_validity_overlap:
            return fail(policy, KSR_POLICY_SIG_OVERLAP_Violation,
                        'Bundle "{}" overlap {} with "{}" is > claimed maximum {}'.format(
                            _fmt_bundle(this), _fmt_timedelta(overlap), _fmt_bundle(previous),
                            _fmt_timedelta(request.zsk_policy.max_validity_overlap),
                        ))
    logger.info(f'KSR-POLICY-SIG-OVERLAP: All bundles overlap in accordance with the stated ZSK operator policy')


def _fmt_bundle(bundle: RequestBundle) -> str:
    return 'id={} {}->{}'.format(bundle.id[:8],
                                 bundle.inception.isoformat().split('T')[0],
                                 bundle.expiration.isoformat().split('T')[0]
                                 )

def _fmt_timedelta(tdelta: timedelta) -> str:
    res = str(tdelta)
    if res.endswith('days, 0:00:00'):
        # cut off the meaningless 0:00:00 after "days"
        res = res[:0 - len(', 0:00:00')]
    return res
