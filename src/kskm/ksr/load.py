"""Top-level functions to load KSRs (Key Signing Requests)."""

import logging
import os

from kskm.common.config_misc import RequestPolicy
from kskm.common.display import log_file_contents
from kskm.common.integrity import checksum_bytes2str, sha256
from kskm.common.parse_utils import signature_policy_from_dict
from kskm.common.validate import PolicyViolation
from kskm.common.xml_parser import parse_ksr
from kskm.ksr.data import Request
from kskm.ksr.parse_utils import requestbundles_from_list_of_dicts
from kskm.ksr.validate import validate_request

__author__ = 'ft'


logger = logging.getLogger(__name__)

MAX_KSR_SIZE = 1024 * 1024


def load_ksr(filename: str, policy: RequestPolicy, raise_original: bool = False, log_contents: bool = False) -> Request:
    """Load a KSR request XML file, and check it according to the RequestPolicy."""
    with open(filename, 'rb') as fd:
        ksr_file_size = os.fstat(fd.fileno()).st_size
        if ksr_file_size > MAX_KSR_SIZE:
            raise RuntimeError(f"KSR exceeding maximum size of {MAX_KSR_SIZE} bytes")
        xml_bytes = fd.read(MAX_KSR_SIZE)  # impose upper limit on how much memory/CPU can be spent loading a file
    logger.info("Loaded KSR from file %s %s", filename, checksum_bytes2str(xml_bytes))
    if log_contents:
        log_file_contents(filename, xml_bytes, logger.getChild('ksr'))
    request = request_from_xml_file(filename, xml_bytes)
    try:
        if validate_request(request, policy) is not True:
            raise RuntimeError('Failed validating KSR request in file {}'.format(filename))
    except PolicyViolation as exc:
        if raise_original:
            # This is better in test cases
            raise
        # This is better in regular operations since it adds information about the context
        raise RuntimeError('Failed validating KSR request in file {}: {}'.format(filename, exc))
    return request


def request_from_xml_file(filename: str, xml_bytes: bytes) -> Request:
    xml_hash = sha256(xml_bytes)
    return request_from_xml(xml_bytes.decode(),
                            xml_filename=filename,
                            xml_hash=xml_hash)


def request_from_xml(xml: str, **kwargs) -> Request:
    """Top-level function to parse a KSR XML document into a Request instance."""
    data = parse_ksr(xml)
    bundles = requestbundles_from_list_of_dicts(data['KSR']['value']['Request'].get('RequestBundle', []))
    zsk_policy = signature_policy_from_dict(data['KSR']['value']['Request']['RequestPolicy']['ZSK'])
    _attrs = data['KSR']['attrs']
    req = Request(id=_attrs['id'],
                  serial=int(_attrs['serial']),
                  domain=_attrs['domain'],
                  zsk_policy=zsk_policy,
                  bundles=bundles,
                  **kwargs
                  )
    return req
