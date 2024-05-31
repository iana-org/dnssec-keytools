"""Key delete functions."""

import logging

import PyKCS11
import PyKCS11.LowLevel

from kskm.keymaster.common import get_session
from kskm.misc.hsm import KSKM_P11, get_p11_key

__author__ = "ft"

logger = logging.getLogger(__name__)


def key_delete(label: str, p11modules: KSKM_P11, force: bool = False) -> bool:
    """Delete a signing key pair from the HSM."""
    existing_key = get_p11_key(label, p11modules, public=True)
    if not existing_key:
        logger.error(f"No key with label {label} found")
        return False

    if not force:
        ack = input(
            f'Delete key pair {existing_key}? Confirm with "Yes" (exactly) or anything else to abort: '
        )
        if ack.strip("\n") != "Yes":
            logger.warning(f"Deletion of key pair {existing_key} aborted")
            return True

    logger.info(f"Deleting key pair {existing_key}")
    session = get_session(p11modules, logger)
    if existing_key.public_key and existing_key.pubkey_handle:
        _destroy_object(session, existing_key.pubkey_handle)
        logger.debug(f"Public key C_DestroyObject executed")

    # Handles seem to get invalidated when calling destroyObject, so do another search for a private key
    existing_key = get_p11_key(label, p11modules, public=False)
    if existing_key and existing_key.privkey_handle:
        _destroy_object(session, existing_key.privkey_handle)
        logger.debug(f"Private key C_DestroyObject executed")
        return True
    return False


def _destroy_object(
    session: PyKCS11.Session, handle: PyKCS11.LowLevel.CK_OBJECT_HANDLE
) -> None:
    """Typed wrapper of session.destroyObject()."""
    session.destroyObject(handle)  # returns None
