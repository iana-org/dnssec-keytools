import logging

import PyKCS11
from kskm.misc.hsm import KSKM_P11


def get_session(p11modules: KSKM_P11, logger: logging.Logger) -> PyKCS11.Session:
    """Get a session, currently with the first slot in the first initialised p11module."""
    first_p11 = p11modules[0]
    if not first_p11.sessions:
        raise RuntimeError('Unable to get a session with the first PKCS#11 module - login problem?')
    first_slot = sorted(first_p11.slots)[0]
    logger.debug(f'Setting up session with first slot ({first_slot}) of P11 module {first_p11}')
    session = first_p11.sessions[first_slot]
    return session
