"""Top-level functions to load SKRs (Signed Key Response)."""
from kskm.common.parse_utils import signature_policy_from_dict
from kskm.common.xml_parser import parse_ksr
from kskm.common.validate import PolicyViolation
from kskm.skr.data import Response
from kskm.skr.policy import ResponsePolicy
from kskm.skr.parse_utils import responsebundles_from_list_of_dicts
from kskm.skr.validate import validate_response


__author__ = 'ft'


def load_skr(fn: str, policy: ResponsePolicy) -> Response:
    """Load a SKR response XML file."""
    with open(fn) as fd:
        xml = fd.read(1024 * 1024)  # impose upper limit on how much memory/CPU can be spent loading a file
    response = response_from_xml(xml)
    try:
        validate_response(response, policy)
    except PolicyViolation as exc:
        raise RuntimeError('Failed validating KSR request in file {}: {}'.format(fn, exc))
    return response


def response_from_xml(xml: str) -> Response:
    """Top-level function to parse a KSR XML document into a Request instance."""
    data = parse_ksr(xml)
    bundles = responsebundles_from_list_of_dicts(data['KSR']['value']['Response']['ResponseBundle'])
    ksk_policy = signature_policy_from_dict(data['KSR']['value']['Response']['ResponsePolicy']['KSK'])
    zsk_policy = signature_policy_from_dict(data['KSR']['value']['Response']['ResponsePolicy']['ZSK'])
    _attrs = data['KSR']['attrs']
    res = Response(id=_attrs['id'],
                   serial=int(_attrs['serial']),
                   domain=_attrs['domain'],
                   bundles=bundles,
                   ksk_policy=ksk_policy,
                   zsk_policy=zsk_policy)
    return res
