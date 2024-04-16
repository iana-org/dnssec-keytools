"""The more testable parts of the ksrsigner tool."""

import logging
from collections.abc import Iterable
from dataclasses import replace

from kskm.common.config import KSKMConfig
from kskm.common.config_misc import KSKPolicy, Schema
from kskm.common.data import AlgorithmPolicy, AlgorithmPolicyRSA, SignaturePolicy
from kskm.common.display import log_file_contents
from kskm.common.integrity import checksum_bytes2str
from kskm.common.rsa_utils import decode_rsa_public_key, is_algorithm_rsa
from kskm.ksr import Request
from kskm.misc.hsm import KSKM_P11
from kskm.signer.sign import sign_bundles
from kskm.skr.data import Response, ResponseBundle
from kskm.skr.output import skr_to_xml

__author__ = "ft"

logger = logging.getLogger(__name__)


def create_skr(
    request: Request, schema: Schema, p11modules: KSKM_P11, config: KSKMConfig
) -> Response:
    """Create a SKR (response) from a request (KSR) and a schema."""
    bundles = sign_bundles(request, schema, p11modules, config.ksk_policy, config)
    return Response(
        id=request.id,
        serial=request.serial,
        domain=request.domain,
        bundles=list(bundles),
        ksk_policy=_ksk_signature_policy(config.ksk_policy, bundles),
        zsk_policy=request.zsk_policy,
        timestamp=None,
    )


def output_skr_xml(
    skr: Response, output_filename: str | None, log_contents: bool = False
) -> None:
    """Return SKR as XML."""
    xml = skr_to_xml(skr)
    if output_filename:
        xml_bytes = xml.encode()
        with open(output_filename, "wb") as fd:
            fd.write(xml_bytes)
        logger.info(
            "Wrote SKR to file %s %s", output_filename, checksum_bytes2str(xml_bytes)
        )
        if log_contents:
            log_file_contents(output_filename, xml_bytes, logger.getChild("skr"))
    else:
        print(xml)


def _ksk_signature_policy(
    ksk_policy: KSKPolicy, bundles: Iterable[ResponseBundle]
) -> SignaturePolicy:
    """Create the statement for what algorithms the SKR response contains."""
    algorithms: set[AlgorithmPolicy] = set()
    for bundle in bundles:
        for key in bundle.keys:
            if is_algorithm_rsa(key.algorithm):
                _pub = decode_rsa_public_key(key.public_key)
                alg = AlgorithmPolicyRSA(
                    exponent=_pub.exponent,
                    bits=_pub.bits,
                    algorithm=key.algorithm,
                )
                algorithms.add(alg)
            else:
                raise NotImplementedError("Only RSA is implemented at this time")
    # update algorithms even though ksk_policy.signature_policy is a frozen BaseModel
    ksk_policy.signature_policy = ksk_policy.signature_policy.model_copy(
        update={"algorithms": algorithms}
    )
    return ksk_policy.signature_policy
