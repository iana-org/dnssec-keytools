"""Output SKR XML documents."""
from typing import Set

from datetime import timedelta

from kskm.common.data import SignaturePolicy, AlgorithmPolicy, AlgorithmPolicyRSA, Key, Signature
from kskm.skr import Response
from kskm.skr.data import ResponseBundle


def skr_to_xml(skr: Response) -> str:
    """Format an SKR as XML."""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<KSR id="{skr.id}" domain="{skr.domain}" serial="{skr.serial}">
    {_indent(_skr_response_to_xml(skr))}
</KSR>
'''


def _skr_response_to_xml(skr: Response) -> str:
    return f'''
<Response>
    {_indent(_skr_response_policy_to_xml(skr))}
    {_indent(_skr_response_bundles_to_xml(skr))}
</Response>
'''


def _skr_response_policy_to_xml(skr: Response) -> str:
    return f'''
<ResponsePolicy>
    {_indent(_skr_response_policy_to_xml2('KSK', skr.ksk_policy))}
    {_indent(_skr_response_policy_to_xml2('ZSK', skr.zsk_policy))}
</ResponsePolicy>
'''


def _skr_response_policy_to_xml2(name: str, policy: SignaturePolicy) -> str:
    return f'''
<{name}>\n
    <PublishSafety>{timedelta_to_duration(policy.publish_safety)}</PublishSafety>
    <RetireSafety>{timedelta_to_duration(policy.retire_safety)}</RetireSafety>
    <MaxSignatureValidity>{timedelta_to_duration(policy.max_signature_validity)}</MaxSignatureValidity>
    <MinSignatureValidity>{timedelta_to_duration(policy.min_signature_validity)}</MinSignatureValidity>
    <MaxValidityOverlap>{timedelta_to_duration(policy.max_validity_overlap)}</MaxValidityOverlap>
    <MinValidityOverlap>{timedelta_to_duration(policy.min_validity_overlap)}</MinValidityOverlap>
    {_indent(_signature_algorithms_to_xml(policy.algorithms))}
</{name}>
'''


def _signature_algorithms_to_xml(algs: Set[AlgorithmPolicy]) -> str:
    res = ''
    for alg in algs:
        if isinstance(alg, AlgorithmPolicyRSA):
            this = f'''
<SignatureAlgorithm algorithm="{alg.algorithm.value}">
    <RSA size="{alg.bits}" exponent="{alg.exponent}"/>
</SignatureAlgorithm>
'''
            res += this
        else:
            raise NotImplementedError('Can only output RSA at the moment')
    return res


def _skr_response_bundles_to_xml(skr: Response) -> str:
    res = ''
    for bundle in skr.bundles:
        res += _skr_bundle_to_xml(bundle)
    return res


def _skr_bundle_to_xml(bundle: ResponseBundle) -> str:
    return f'''
<ResponseBundle id="{bundle.id}">
    <Inception>{bundle.inception}</Inception>
    <Expiration>{bundle.expiration}</Expiration>
    {_indent(_skr_keys_to_xml(bundle))}
    {_indent(_skr_signatures_to_xml(bundle))}
</ResponseBundle>
'''


def _skr_keys_to_xml(bundle: ResponseBundle) -> str:
    return ''.join([_skr_key_to_xml(key) for key in bundle.keys])


def _skr_key_to_xml(key: Key) -> str:
    return f'''
<Key keyIdentifier="{key.key_identifier}" keyTag="{key.key_tag}">
    <TTL>{key.ttl}</TTL>
    <Flags>{key.flags}</Flags>
    <Protocol>{key.protocol}</Protocol>
    <Algorithm>{key.algorithm.value}</Algorithm>
    <PublicKey>{key.public_key.decode('UTF-8')}</PublicKey>
</Key>
'''


def _skr_signatures_to_xml(bundle: ResponseBundle) -> str:
    return ''.join([_skr_signature_to_xml(sig) for sig in bundle.signatures])


def _skr_signature_to_xml(sig: Signature) -> str:
    return f'''
<Signature keyIdentifier="{sig.key_identifier}">
    <TTL>{sig.ttl}</TTL>
    <TypeCovered>{sig.type_covered.name}</TypeCovered>
    <Algorithm>{sig.algorithm.value}</Algorithm>
    <Labels>{sig.labels}</Labels>
    <OriginalTTL>{sig.original_ttl}</OriginalTTL>
    <SignatureExpiration>{sig.signature_expiration}</SignatureExpiration>
    <SignatureInception>{sig.signature_inception}</SignatureInception>
    <KeyTag>{sig.key_tag}</KeyTag>
    <SignersName>{sig.signers_name}</SignersName>
    <SignatureData>{sig.signature_data.decode('UTF-8')}</SignatureData>
</Signature>
'''


def _indent(data: str) -> str:
    res = []
    for this in data.split('\n'):
        if not this:  # skip blank lines
            continue
        res += [' ' * 4 + this]
    res2 = '\n'.join(res)
    # left-strip for prettier formatting where the returned data is incorporated in an f-string
    return res2.lstrip()


def timedelta_to_duration(td: timedelta) -> str:
    """Format a timedelta as an ISO8601 duration (e.g. P21D, PT0S, P5DT4M)."""
    if td.total_seconds() == 0:
        return 'PT0S'
    days = f'P{td.days}D' if td.days else 'P'
    time = ''
    if td.seconds:
        _t = td.seconds
        if _t > 3600:
            time += f'{_t // 3600}H'
            _t = _t % 3600
        if _t > 60:
            time += f'{_t // 60}M'
            _t = _t % 60
        if _t:
            time += f'{_t}S'
        time = f'T{_t}'
    return days + time
