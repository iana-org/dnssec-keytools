"""Top-level functions to load SKRs (Signed Key Response)."""

import logging
import os

from kskm.common.config_misc import ResponsePolicy
from kskm.common.display import log_file_contents
from kskm.common.integrity import checksum_bytes2str
from kskm.common.parse_utils import signature_policy_from_dict
from kskm.common.validate import PolicyViolation
from kskm.common.xml_parser import parse_ksr
from kskm.skr.data import Response
from kskm.skr.parse_utils import responsebundles_from_list_of_dicts
from kskm.skr.validate import validate_response

__author__ = 'ft'
logger = logging.getLogger(__name__)

MAX_SKR_SIZE = 1024 * 1024


def load_skr(filename: str, policy: ResponsePolicy) -> Response:
    """Load a SKR response XML file."""
    with open(filename, 'rb') as fd:
        skr_file_size = os.fstat(fd.fileno()).st_size
        if skr_file_size > MAX_SKR_SIZE:
            raise RuntimeError(f"SKR exceeding maximum size of {MAX_SKR_SIZE} bytes")
        xml_bytes = fd.read(MAX_SKR_SIZE)  # impose upper limit on how much memory/CPU can be spent loading a file
    logger.info("Loaded SKR from file %s %s", filename, checksum_bytes2str(xml_bytes))
    log_file_contents(filename, xml_bytes, logger.getChild('skr'))
    response = response_from_xml(xml_bytes.decode())
    try:
        validate_response(response, policy)
    except PolicyViolation as exc:
        raise RuntimeError('Failed validating SKR response in file {}: {}'.format(filename, exc))
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
