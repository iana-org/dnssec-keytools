import logging

from kskm.keymaster.common import get_session
from kskm.misc.hsm import KSKM_P11, get_p11_key, get_p11_secret_key

__author__ = 'ft'

logger = logging.getLogger(__name__)


def key_delete(label: str, p11modules: KSKM_P11, force: bool=False) -> bool:
    """Delete a signing key pair from the HSM."""
    existing_key = get_p11_key(label, p11modules, public=True)
    if not existing_key:
        logger.error(f'No key with label {label} found')
        return False

    if not force:
        ack = input(f'Delete key pair {existing_key}? Confirm with "Yes" (exactly) or anything else to abort: ')
        if ack.strip('\n') != 'Yes':
            logger.info(f'Deletion of key pair {existing_key} aborted')
            return True

    logger.info(f'Deleting key pair {existing_key}')
    session = get_session(p11modules, logger)
    if existing_key.public_key:
        res = session.destroyObject(existing_key.pubkey_handle[0])
        logger.debug(f'Public key C_DestroyObject result: {res}')

    # Handles seem to get invalidated when calling destroyObject, so do another search for a private key
    existing_key = get_p11_key(label, p11modules, public=False)
    if existing_key.private_key:
        res = session.destroyObject(existing_key.private_key[0])
        logger.debug(f'Private key C_DestroyObject result: {res}')
        return True
    return False


def wrapkey_delete(label: str, p11modules: KSKM_P11, force: bool=False) -> bool:
    """Delete a wrapping (secret) key from the HSM."""
    existing_key = get_p11_secret_key(label, p11modules)
    if not existing_key:
        logger.error(f'No secret key with label {label} found')
        return False

    if not force:
        ack = input(f'Delete secret key {existing_key}? Confirm with "Yes" (exactly) or anything else to abort: ')
        if ack.strip('\n') != 'Yes':
            logger.info(f'Deletion of key {existing_key} aborted')
            return True

    logger.info(f'Deleting secret key {existing_key}')
    session = get_session(p11modules, logger)
    if existing_key.private_key:
        res = session.destroyObject(existing_key.private_key[0])
        logger.debug(f'Private key C_DestroyObject result: {res}')
    return True
