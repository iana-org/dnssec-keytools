"""Sign request bundles and return response bundles."""

import base64
import hashlib
import logging
from collections.abc import Iterable

from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel

from kskm.common.config import ConfigurationError, KSKKeysType, KSKMConfig
from kskm.common.config_ksk import validate_dnskey_matches_ksk
from kskm.common.config_misc import KSKPolicy, Schema
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY, Key, Signature, TypeDNSSEC
from kskm.common.dnssec import calculate_key_tag
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.signature import dndepth, make_raw_rrsig
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, KSKM_P11Key, sign_using_p11
from kskm.signer.key import CompositeKey, load_pkcs11_key
from kskm.skr.data import ResponseBundle
from kskm.skr.validate import check_valid_signatures

__author__ = "ft"

logger = logging.getLogger(__name__)


class CreateSignatureError(Exception):
    """Failures to create a signature."""


class SKR_VERIFY_Failure(InvalidSignature):
    """SKR-VERIFY signature validation failure."""


def sign_bundles(
    request: Request,
    schema: Schema,
    p11modules: KSKM_P11,
    ksk_policy: KSKPolicy,
    config: KSKMConfig,
) -> Iterable[ResponseBundle]:
    """
    Execute the actions specified in the schema, for all bundles in the request.

    This is typically to add one or more KSK keys to the key set, and then sign the
    DNSKEY RR set using the KSK key stored in a PKCS#11 module (HSM).
    """
    res: list[ResponseBundle] = []
    for bundle_num, _bundle in enumerate(request.bundles, 1):
        this_schema = schema.actions[bundle_num]

        if _bundle.signers:
            logger.warning(
                f"Bundle {_bundle.id} has signers specified - those will be ignored"
            )

        updated_keys = UpdatedKeys(ksk_policy_ttl=ksk_policy.ttl)

        #
        # Add all the 'publish' keys (KSK operator keys) to the keys already in the bundle (ZSK operator keys)
        #
        for this_key in _fetch_keys(
            this_schema.publish, _bundle, p11modules, ksk_policy, config.ksk_keys, True
        ):
            updated_keys.add(this_key.dns)
        #
        # Add all the 'revoke' keys (same as 'publish' but the key gets the revoke flag bit set)
        #
        for this_key in _fetch_keys(
            this_schema.revoke, _bundle, p11modules, ksk_policy, config.ksk_keys, True
        ):
            revoked_key = this_key.dns.replace(
                flags=this_key.dns.flags | FlagsDNSKEY.REVOKE.value
            )
            revoked_key = revoked_key.replace(key_tag=calculate_key_tag(revoked_key))
            updated_keys.update(revoked_key)
        #
        # All the signing keys sign the complete DNSKEY RRSET, so first add them to the bundles keys
        #
        signing_keys = _fetch_keys(
            this_schema.sign, _bundle, p11modules, ksk_policy, config.ksk_keys, False
        )
        for this_key in signing_keys:
            updated_keys.add(this_key.dns)

        # Add the keys from the request bundle too.
        for _key in _bundle.keys:
            updated_keys.add(_key)

        #
        # Using the 'signing' keys for this bundle in the schema, sign all the keys in the bundle
        #
        signatures: set[Signature] = set()
        for _sign_key in signing_keys:
            _sig = _sign_keys(_bundle, updated_keys, _sign_key, ksk_policy)
            if _sig:
                signatures.add(_sig)

        # Ensure the ZSK set of algorithms covering this bundle match the KSK set of algorithms
        _zsk_algs = {x.algorithm.name for x in _bundle.keys}
        _ksk_algs = {x.algorithm.name for x in signatures}
        if _zsk_algs != _ksk_algs:
            raise CreateSignatureError(
                f"ZSK algorithms {_zsk_algs} does not match KSK algorithms {_ksk_algs} "
                f"for bundle {_bundle.id}"
            )

        response_bundle = ResponseBundle(
            id=_bundle.id,
            inception=_bundle.inception,
            expiration=_bundle.expiration,
            keys=updated_keys.keys,
            signatures=signatures,
        )
        #
        # For good measure, apply response policy validation
        #
        check_valid_signatures(response_bundle, config.response_policy)
        res += [response_bundle]

    return res


class UpdatedKeys(BaseModel):
    """Class to hold a set of keys to be signed, ensuring uniqueness and TTL according to policy."""

    ksk_policy_ttl: int
    keys: set[Key] = set()

    _hush_key_ttl_warnings: set[str] = set()

    def _add_unique(self, key: Key) -> None:
        """Add a key to a set, ensuring uniqueness."""
        for _key in self.keys:
            if _key.public_key == key.public_key:
                return None

        if key.ttl != self.ksk_policy_ttl:
            if key.key_identifier not in self._hush_key_ttl_warnings:
                logger.warning(
                    f"Overriding key {key.key_identifier} TTL {key.ttl} -> {self.ksk_policy_ttl}"
                )
                if key.key_identifier:
                    self._hush_key_ttl_warnings.add(key.key_identifier)
            key = key.replace(ttl=self.ksk_policy_ttl)

        self.keys.add(key)

    def add(self, key: Key) -> None:
        """Add a key to the set, ensuring uniqueness and TTL according to policy."""
        self._add_unique(key)

    def update(self, key: Key) -> None:
        """Same as `add`, but replace the key if it already exists."""
        # remove key from keys
        for _this in self.keys:
            if _this.public_key == key.public_key:
                self.keys.remove(_this)
                break
        self._add_unique(key)

    def get(self, key_identifier: str) -> Key | None:
        """Get a key from the set by key identifier."""
        for _key in self.keys:
            if _key.key_identifier == key_identifier:
                return _key
        return None


def _fetch_keys(
    key_names: Iterable[str],
    bundle: RequestBundle,
    p11modules: KSKM_P11,
    ksk_policy: KSKPolicy,
    ksk_keys: KSKKeysType,
    public: bool,
) -> Iterable[CompositeKey]:
    res: list[CompositeKey] = []
    for _name in key_names:
        ksk = ksk_keys[_name]
        this_key = load_pkcs11_key(ksk, p11modules, ksk_policy, bundle, public=public)
        if not this_key:
            logger.error(
                f"Could not find key {repr(_name)} ({ksk.label}/{ksk.description}) "
                f"for bundle {bundle.id}"
            )
            raise ConfigurationError(f"Key {repr(_name)} not found")

        # Ensure the right key was located
        validate_dnskey_matches_ksk(ksk, this_key.dns)
        res += [this_key]
    return res


def _sign_keys(
    bundle: RequestBundle,
    updated_keys: UpdatedKeys,
    signing_key: CompositeKey,
    ksk_policy: KSKPolicy,
) -> Signature | None:
    """Sign the bundle key RRSET using the HSM key identified by 'label'."""
    logger.debug(f"Signing {len(updated_keys.keys)} bundle keys:")
    for _this in updated_keys.keys:
        logger.debug(f"  {_this}")
    logger.debug(
        f"Signing above {len(updated_keys.keys)} bundle keys with sign_key {signing_key}"
    )

    # All ZSK TTLs are guaranteed to be the same as ksk_policy.ttl at this point. Just do this for clarity.
    for _key in updated_keys.keys:
        if _key.ttl != ksk_policy.ttl:
            raise CreateSignatureError(
                f"Key {_key.key_identifier} has TTL {_key.ttl} != {ksk_policy.ttl}"
            )

    # To get the right key tag for revoked keys, we need to locate the signing key in the set of
    # updated keys and use that key tag in the signature below.
    _dns_key = updated_keys.get(signing_key.dns.key_identifier)
    if not _dns_key:
        raise CreateSignatureError(
            f"Could not find signing key {signing_key.dns.key_identifier} in bundle {bundle.id}"
        )

    sig = Signature(
        key_tag=_dns_key.key_tag,
        key_identifier=signing_key.dns.key_identifier,
        signature_expiration=bundle.expiration,
        signature_inception=bundle.inception,
        type_covered=TypeDNSSEC.DNSKEY,
        algorithm=signing_key.dns.algorithm,
        original_ttl=ksk_policy.ttl,
        ttl=ksk_policy.ttl,
        signers_name=ksk_policy.signers_name,
        labels=dndepth(ksk_policy.signers_name),
        signature_data=b"",  # Will replace this below
    )

    rrsig_raw = make_raw_rrsig(sig, updated_keys.keys)
    signature_data = sign_using_p11(
        signing_key.p11, rrsig_raw, signing_key.dns.algorithm
    )

    # Before proceeding, validate the signature using a non-HSM based implementation
    try:
        _verify_using_crypto(
            signing_key.p11, rrsig_raw, signature_data, signing_key.dns.algorithm
        )
    except InvalidSignature as exc:
        raise SKR_VERIFY_Failure(
            f"Invalid KSK signature encountered in bundle {bundle.id}"
        ) from exc

    sig = sig.replace(signature_data=base64.b64encode(signature_data))
    return sig


def _verify_using_crypto(
    p11_key: KSKM_P11Key, rrsig_raw: bytes, signature: bytes, algorithm: AlgorithmDNSSEC
) -> None:
    """Double-check signatures created using HSM with a standard software cryptographic library."""
    if p11_key.public_key is None:
        raise RuntimeError(f"Can't verify signature without public key ({p11_key})")
    try:
        pubkey = KSKM_PublicKey.from_bytes(p11_key.public_key, algorithm)
        pubkey.verify_signature(signature, rrsig_raw)
        logger.debug("Signature validated with software")
    except InvalidSignature:
        logger.error("Failed validating the signature created by the HSM")
        logger.debug("RRSIG : %s", base64.b16encode(rrsig_raw))
        logger.debug("DIGEST: %s", hashlib.sha256(rrsig_raw).hexdigest())
        logger.debug("SIG   : %s", base64.b16encode(signature))
        raise
