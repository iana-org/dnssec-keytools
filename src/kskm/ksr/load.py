"""Top-level functions to load KSRs (Key Signing Requests)."""
from kskm.ksr.data import Request
from kskm.ksr.policy import RequestPolicy
from kskm.ksr.validate import validate_request
from kskm.common.validate import PolicyViolation
from kskm.common.xml_parser import parse_ksr
from kskm.common.parse_utils import signature_policy_from_dict
from kskm.ksr.parse_utils import requestbundles_from_list_of_dicts


__author__ = 'ft'


def load_ksr(fn: str, policy: RequestPolicy, raise_original: bool=False) -> Request:
    """Load a KSR request XML file, and check it according to the RequestPolicy."""
    with open(fn) as fd:
        xml = fd.read(1024 * 1024)  # impose upper limit on how much memory/CPU can be spent loading a file
    request = request_from_xml(xml)
    try:
        if validate_request(request, policy) is not True:
            raise RuntimeError('Failed validating KSR request in file {}'.format(fn))
    except PolicyViolation as exc:
        if raise_original:
            # This is better in test cases
            raise
        # This is better in regular operations since it adds information about the context
        raise RuntimeError('Failed validating KSR request in file {}: {}'.format(fn, exc))
    return request


def request_from_xml(xml: str) -> Request:
    """Top-level function to parse a KSR XML document into a Request instance."""
    data = parse_ksr(xml)
    bundles = requestbundles_from_list_of_dicts(data['KSR']['value']['Request']['RequestBundle'])
    zsk_policy = signature_policy_from_dict(data['KSR']['value']['Request']['RequestPolicy']['ZSK'])
    _attrs = data['KSR']['attrs']
    req = Request(id=_attrs['id'],
                  serial=int(_attrs['serial']),
                  domain=_attrs['domain'],
                  zsk_policy=zsk_policy,
                  bundles=bundles,
                  )
    return req
