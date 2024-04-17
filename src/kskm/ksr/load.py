"""Top-level functions to load KSRs (Key Signing Requests)."""

import logging
import os
from pathlib import Path
from typing import Any

from kskm.common.config_misc import RequestPolicy
from kskm.common.display import log_file_contents
from kskm.common.integrity import checksum_bytes2str, sha256
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.validate import PolicyViolation
from kskm.common.xml_parser import parse_ksr
from kskm.ksr.data import Request
from kskm.ksr.parse_utils import requestbundles_from_list_of_dicts
from kskm.ksr.validate import validate_request

__author__ = "ft"


logger = logging.getLogger(__name__)

MAX_KSR_SIZE = 1024 * 1024


def load_ksr(
    filename: Path,
    policy: RequestPolicy,
    raise_original: bool = False,
    log_contents: bool = False,
) -> Request:
    """Load a KSR request XML file, and check it according to the RequestPolicy."""
    with open(filename, "rb") as fd:
        ksr_file_size = os.fstat(fd.fileno()).st_size
        if ksr_file_size > MAX_KSR_SIZE:
            raise RuntimeError(f"KSR exceeding maximum size of {MAX_KSR_SIZE} bytes")
        xml_bytes = fd.read(
            MAX_KSR_SIZE
        )  # impose upper limit on how much memory/CPU can be spent loading a file
    logger.info("Loaded KSR from file %s %s", filename, checksum_bytes2str(xml_bytes))
    if log_contents:
        log_file_contents(filename, xml_bytes, logger.getChild("ksr"))
    request = request_from_xml_file(filename, xml_bytes)
    try:
        if validate_request(request, policy) is not True:
            raise RuntimeError(f"Failed validating KSR request in file {filename}")
    except PolicyViolation as exc:
        if raise_original:
            # This is better in test cases
            raise
        # This is better in regular operations since it adds information about the context
        raise RuntimeError(
            f"Failed validating KSR request in file {filename}: {exc}"
        ) from exc
    return request


def request_from_xml_file(filename: Path, xml_bytes: bytes) -> Request:
    """Parse XML data and return Request instance."""
    xml_hash = sha256(xml_bytes)
    return request_from_xml(
        xml_bytes.decode(), xml_filename=filename, xml_hash=xml_hash
    )


def request_from_xml(xml: str, **kwargs: Any) -> Request:
    """Top-level function to parse a KSR XML document into a Request instance."""
    data = parse_ksr(xml)
    bundles_list = data["KSR"]["value"]["Request"].get("RequestBundle", [])
    if not isinstance(bundles_list, list):
        # handle a single RequestBundle in the request
        bundles_list = [bundles_list]
    bundles = requestbundles_from_list_of_dicts(bundles_list)
    zsk_policy = signature_policy_from_dict(
        data["KSR"]["value"]["Request"]["RequestPolicy"]["ZSK"]
    )
    _attrs = data["KSR"]["attrs"]
    timestamp = None
    if "timestamp" in _attrs:
        timestamp = parse_datetime(_attrs["timestamp"])
    req = Request(
        id=_attrs["id"],
        serial=int(_attrs["serial"]),
        domain=_attrs["domain"],
        timestamp=timestamp,
        zsk_policy=zsk_policy,
        bundles=bundles,
        **kwargs,
    )
    return req
