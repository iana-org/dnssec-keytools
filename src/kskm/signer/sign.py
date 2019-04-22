"""Sign request bundles and return response bundles."""
import base64
import hashlib
import logging
from dataclasses import replace
from typing import Dict, Iterable, List, Optional

from cryptography.exceptions import InvalidSignature

from kskm.common.config import (ConfigurationError, KSKMConfig)
from kskm.common.config_misc import KSKKeysType, KSKPolicy, Schema, SchemaAction
from kskm.common.data import AlgorithmDNSSEC, Key, Signature, TypeDNSSEC
from kskm.common.signature import dndepth, make_raw_rrsig
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.crypto import pubkey_to_crypto_pubkey, verify_signature
from kskm.misc.hsm import KSKM_P11, KSKM_P11Key, sign_using_p11
from kskm.signer.key import load_pkcs11_key
from kskm.skr.data import ResponseBundle

logger = logging.getLogger(__name__)


class CreateSignatureError(Exception):
    pass


def sign_bundles(request: Request, schema: Schema, p11modules: KSKM_P11,
                 ksk_policy: KSKPolicy, config: KSKMConfig) -> Iterable[ResponseBundle]:
    """
    Execute the actions specified in the schema, for all bundles in the request.

    This is typically to add one or more KSK keys to the key set, and then sign the
    DNSKEY RR set using the KSK key stored in a PKCS#11 module (HSM).
    """
    res: List[ResponseBundle] = []
    bundle_num = 0
    _hush_key_ttl_warnings: Dict[str, bool] = {}
    for _bundle in request.bundles:
        bundle_num += 1
        this_schema = schema.actions[bundle_num]

        # All DNSKEY RRs in a set *has* to have the same TTL. Ensure all keys have the TTL
        # configured by the KSK operator. A warning is logged for any discrepancies found,
        # because an earlier policy check (KSR-POLICY-KEYS) should have found this unless disabled.
        _new_keys = set()
        for _key in _bundle.keys:
            if _key.ttl != ksk_policy.ttl:
                if _key.key_identifier not in _hush_key_ttl_warnings:
                    logger.warning(f'Overriding key {_key.key_identifier} TTL {_key.ttl} -> {ksk_policy.ttl}')
                    if _key.key_identifier is not None:
                        _hush_key_ttl_warnings[_key.key_identifier] = True
                _key = replace(_key, ttl=ksk_policy.ttl)
            _new_keys.add(_key)
        #
        # Load all the 'publish' keys from the PKCS#11 backends and format them as Key instances
        #
        publish_keys = _schema_action_to_publish_keys(_bundle, this_schema, p11modules, ksk_policy, config.ksk_keys)
        # Add all the 'publish' keys (KSK operator keys) to the keys already in the bundle (ZSK operator keys)
        _new_keys.update(publish_keys)
        updated_bundle = replace(_bundle, keys=_new_keys)

        #
        # Using the 'signing' keys for this bundle in the schema, sign all the keys in the bundle
        #
        signatures = set()
        for _sign_key in this_schema.sign:
            logger.debug(f'Signing keys {updated_bundle.keys} with sign_key {_sign_key}')
            _sig = _sign_keys(updated_bundle, _sign_key, p11modules, ksk_policy, config.ksk_keys)
            if _sig:
                signatures.add(_sig)

        # Ensure the ZSK set of algorithms covering this bundle match the KSK set of algorithms
        _zsk_algs = set([x.algorithm.name for x in _bundle.keys])
        _ksk_algs = set([x.algorithm.name for x in signatures])
        if _zsk_algs != _ksk_algs:
            raise CreateSignatureError(f'ZSK algorithms {_zsk_algs} does not match KSK algorithms {_ksk_algs} '
                                       f'for bundle {_bundle.id}')

        # TODO: Ensure we got signatures covering all the ZSK keys in the bundle
        res += [ResponseBundle(id=_bundle.id,
                               inception=_bundle.inception,
                               expiration=_bundle.expiration,
                               keys=_new_keys,
                               signatures=signatures)]
    return res


def _schema_action_to_publish_keys(bundle: RequestBundle, s_action: SchemaAction, p11modules: KSKM_P11,
                                   ksk_policy: KSKPolicy, ksk_keys: KSKKeysType) -> Iterable[Key]:
    res: List[Key] = []
    # Load the keys the KSK operator wants to add to the ones provided by the ZSK operator
    for _publish_key in s_action.publish:
        ksk = ksk_keys[_publish_key]
        this_key = load_pkcs11_key(ksk, p11modules, ksk_policy, bundle, public=True)
        if not this_key:
            logger.error(f'Could not find publish key {_publish_key!r} ({ksk.label}/{ksk.description}) '
                         f'for bundle {bundle.id}')
            raise ConfigurationError(f'Key {_publish_key!r} not found')
        res += [this_key.dns]
    return res


def _sign_keys(bundle: RequestBundle, sign_key_name: str, p11modules: KSKM_P11,
               ksk_policy: KSKPolicy, ksk_keys: KSKKeysType) -> Optional[Signature]:
    """
    Sign the bundle key RRSET using the HSM key identified by 'label'.
    """
    ksk = ksk_keys[sign_key_name]
    this_key = load_pkcs11_key(ksk, p11modules, ksk_policy, bundle, public=False)
    if not this_key:
        logger.error(f'Could not find signing key {sign_key_name!r} ({ksk.label}/{ksk.description}) '
                     f'for bundle {bundle.id}')
        raise ConfigurationError(f'Key {sign_key_name!r} not found')

    signing_key = this_key.dns

    # All ZSK TTLs are guaranteed to be the same as ksk_policy.ttl at this point. Just do this for clarity.
    for _key in bundle.keys:
        if _key.ttl != ksk_policy.ttl:
            raise CreateSignatureError(f'TTL mismatch between ZSK and KSK in bundle {bundle.id}')

    sig = Signature(
        key_tag=signing_key.key_tag,
        key_identifier=signing_key.key_identifier,
        signature_expiration=bundle.expiration,
        signature_inception=bundle.inception,
        type_covered=TypeDNSSEC.DNSKEY,
        algorithm=signing_key.algorithm,
        original_ttl=ksk_policy.ttl,
        ttl=ksk_policy.ttl,
        signers_name=ksk_policy.signers_name,
        labels=dndepth(ksk_policy.signers_name),
        signature_data=b'',  # Will replace this below
    )

    rrsig_raw = make_raw_rrsig(sig, bundle.keys)
    signature_data = sign_using_p11(this_key.p11, rrsig_raw, signing_key.algorithm)

    # Before proceeding, validate the signature using a non-HSM based implementation
    _verify_using_crypto(this_key.p11, rrsig_raw, signature_data, signing_key.algorithm)

    sig = replace(sig, signature_data=base64.b64encode(signature_data))
    return sig


def _verify_using_crypto(p11_key: KSKM_P11Key, rrsig_raw: bytes, signature: bytes,
                         algorithm: AlgorithmDNSSEC) -> None:
    """Double-check signatures created using HSM with a standard software cryptographic library."""
    pubkey = pubkey_to_crypto_pubkey(p11_key.public_key)
    try:
        verify_signature(pubkey, signature, rrsig_raw, algorithm)
        logger.debug('Signature validated with software')
    except InvalidSignature:
        logger.error('Failed validating the signature created by the HSM')
        logger.debug('RRSIG : {}'.format(base64.b16encode(rrsig_raw)))
        logger.debug('DIGEST: {}'.format(hashlib.sha256(rrsig_raw).hexdigest()))
        logger.debug('SIG   : {}'.format(base64.b16encode(signature)))
        raise
