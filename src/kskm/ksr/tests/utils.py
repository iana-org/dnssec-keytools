import base64
import binascii
import io
import os

import pkg_resources

from kskm.common.data import AlgorithmDNSSEC
from kskm.misc.hsm import get_p11_key, sign_using_p11


def sign_using_softhsm(data: bytes, softhsm_signing_key: str = "RSA1") -> None:
    """
    Calculate the correct ZSK operator signature using the key in SoftHSM.

    Look at the error message given when an invalid signature is found, and pass the RRSIG
    bytes as `data' to this function to get the correct signature value.
    """
    import hashlib

    from kskm.common.config import KSKMConfig
    from kskm.misc.hsm import init_pkcs11_modules_from_dict

    softhsm_dir = pkg_resources.resource_filename(
        __name__, "../../../../testing/softhsm"
    )
    _cfg_fn = os.path.join(softhsm_dir, "ksrsigner.yaml")

    with open(_cfg_fn) as fd:
        conf = io.StringIO(fd.read())
    config = KSKMConfig.from_yaml(conf)
    p11modules = init_pkcs11_modules_from_dict(config.hsm)

    signing_key = get_p11_key(softhsm_signing_key, p11modules, public=False)
    assert signing_key is not None
    rrsig = binascii.unhexlify(data)
    signature_data = sign_using_p11(signing_key, rrsig, AlgorithmDNSSEC.RSASHA256)
    correct_sig = base64.b64encode(signature_data)

    print(
        f"Correct signature (using key {softhsm_signing_key}) for RRSIG {binascii.hexlify(rrsig).decode()}\n"
        f" (SHA-256 digest {hashlib.sha256(rrsig).hexdigest()}):\n{correct_sig.decode()}"
    )
