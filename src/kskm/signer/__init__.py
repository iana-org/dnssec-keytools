"""The more testable parts of the ksrsigner tool."""
import logging

from dataclasses import replace
from typing import Iterable, Set

from kskm.ksr import Request
from kskm.signer.sign import sign_bundles
from kskm.skr.data import Response, ResponseBundle
from kskm.misc.hsm import KSKM_P11
from kskm.common.data import SignaturePolicy
from kskm.common.data import AlgorithmPolicy, AlgorithmPolicyRSA
from kskm.common.config import get_ksk_policy, KSKPolicy
from kskm.common.config import ConfigType, Schema
from kskm.common.rsa_utils import is_algorithm_rsa, decode_rsa_public_key

__author__ = 'ft'

logger = logging.getLogger(__name__)


def create_skr(request: Request, schema: Schema, p11modules: KSKM_P11, config: ConfigType) -> Response:
    """Create a SKR (response) from a request (KSR) and a schema."""
    ksk_policy = get_ksk_policy(config)
    bundles = sign_bundles(request, schema, p11modules, ksk_policy, config)
    return Response(id=request.id,
                    serial=request.serial,
                    domain=request.domain,
                    bundles=bundles,
                    ksk_policy=_ksk_signature_policy(ksk_policy, bundles),
                    zsk_policy=request.zsk_policy)


def output_skr_xml(skr: Response) -> str:
    """Return SKR as XML."""
    pass


def _ksk_signature_policy(ksk_policy: KSKPolicy, bundles: Iterable[ResponseBundle]) -> SignaturePolicy:
    """Create the statement for what algorithms the SKR response contains."""
    algorithms: Set[AlgorithmPolicy] = set()
    for bundle in bundles:
        for key in bundle.keys:
            if is_algorithm_rsa(key.algorithm):
                _pub = decode_rsa_public_key(key.public_key)
                alg = AlgorithmPolicyRSA(exponent=_pub.exponent,
                                         bits=_pub.bits,
                                         )
                algorithms.add(alg)
            else:
                raise NotImplementedError('Only RSA is implemented at this time')
    return replace(ksk_policy.signature_policy, algorithms=algorithms)
