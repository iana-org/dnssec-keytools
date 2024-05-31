"""Code using the Cryptography library."""

import logging
from typing import Self

from pydantic import BaseModel

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicy, Key
from kskm.common.ecdsa_utils import KSKM_PublicKey_ECDSA, is_algorithm_ecdsa
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import KSKM_PublicKey_RSA, is_algorithm_rsa

__author__ = "ft"

logger = logging.getLogger(__name__)
