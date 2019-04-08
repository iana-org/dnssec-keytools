"""Hardware Security Module interface functions."""
from __future__ import annotations

import base64
import glob
import logging
import os
import re
from dataclasses import dataclass, field
from getpass import getpass
from typing import (Any, Dict, Iterator, List, Mapping, MutableMapping,
                    NewType, Optional)

import PyKCS11

from kskm.common.rsa_utils import RSAPublicKeyData

__author__ = 'ft'


logger = logging.getLogger(__name__)


@dataclass
class KSKM_P11Key(object):
    """A reference to a key object loaded from a PKCS#11 module."""

    label: str  # for debugging
    public_key: RSAPublicKeyData
    private_key: Any = field(repr=False)  # PyKCS11 opaque data
    session: Any = field(repr=False)  # PyKCS11 opaque data


class KSKM_P11Module(object):
    """KSKM interface to a PKCS#11 module."""

    def __init__(self, module: str, label: Optional[str] = None, pin: Optional[str] = None, env: Dict[str, str] = {}):
        """Load and initialise a PKCS#11 module."""

        if module.startswith('$'):
            self.module = os.environ.get(module.lstrip('$'))
        else:
            self.module = module

        if label is None:
            self.label = module
        else:
            self.label = label

        logger.info('Initializing PKCS#11 module %s using %s', self.label, self.module)

        # configure environment
        old_env = {}
        for key in env.keys():
            old_env[key] = os.environ.get(key)
        os.environ.update(env)

        # load module
        self._lib = PyKCS11.PyKCS11Lib()
        self._lib.load(self.module)
        self._lib.lib.C_Initialize()

        # reset environment
        for k, v in old_env.items():
            if v is None:
                del(os.environ[k])
            else:
                os.environ[k] = v

        # set PIN
        if pin is None:
            self.pin = getpass(f"Enter PIN for PKCS#11 module {self.label}: ")
        else:
            self.pin = str(pin)

        # Mapping from slot number to session
        self._sessions: Dict[int, Any] = {}

        self._slots = self._lib.getSlotList(tokenPresent=True)
        logger.debug('P11 slots: {!r}'.format(self._slots))

    @property
    def sessions(self) -> Mapping[int, Any]:
        """Get sessions for all slots."""
        if not self._sessions:
            for _slot in self._slots:
                try:
                    logger.debug(f'Opening slot {_slot} in module {self.label}')
                    _session = self._lib.openSession(_slot)
                    if self.pin is not None and len(self.pin) > 0:
                        _session.login(self.pin)
                        logger.debug(f'Login to module {self.label} slot {_slot} successful')
                    else:
                        logger.info(f'Not logging in to module {self.label} slot {_slot} - no PIN provided')
                    self._sessions[_slot] = _session
                except PyKCS11.PyKCS11Error:
                    logger.warning(f'Login to module {self.label} slot {_slot} failed')
        return self._sessions

    def find_key_by_label(self, label: str, public: bool = True) -> Optional[KSKM_P11Key]:
        """
        Query the PKCS#11 module for a key with CKA_LABEL matching 'label'.

        If 'public' is True, a CKO_PUBLIC_KEY will be sought, otherwise CKO_PRIVATE_KEY.
        """
        for _slot, _session in self.sessions.items():
            template = [(PyKCS11.CKA_LABEL, label)]
            if public:
                template += [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)]
            else:
                template += [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]
            res = _session.findObjects(template)
            if res:
                # logger.debug(f'Found key with label {label!r} in slot {_slot}')
                return KSKM_P11Key(label=label,
                                   public_key=self._p11_object_to_public_key(_session, res),
                                   private_key=res if not public else None,
                                   session=_session,
                                   )
        logger.debug(f'Key with label {label!r} not found')
        return None

    @staticmethod
    def _p11_object_to_public_key(session: Any, data: list) -> RSAPublicKeyData:
        """Create an RSAPublicKeyData object from PKCS#11 findObject return data."""
        _cka_type = session.getAttributeValue(data[0], [PyKCS11.CKA_KEY_TYPE])[0]
        if _cka_type == PyKCS11.CKK_RSA:
            _modulus = session.getAttributeValue(data[0], [PyKCS11.CKA_MODULUS])
            _exp = session.getAttributeValue(data[0], [PyKCS11.CKA_PUBLIC_EXPONENT])
            rsa_e = int.from_bytes(bytes(_exp[0]), byteorder='big')
            rsa_n = bytes(_modulus[0])
            return RSAPublicKeyData(bits=len(rsa_n) * 8,
                                    exponent=rsa_e,
                                    n=rsa_n)
        else:
            raise NotImplementedError('Unknown CKA_TYPE: {}'.format(PyKCS11.CKK[_cka_type]))


def sign_using_p11(key: KSKM_P11Key, data: bytes) -> bytes:
    """
    Sign some data using a PKCS#11 key.

    NOTE: The old code seemed to be pretty deliberately made to create the raw data
          itself and then ask the HSM to sign raw data (using CKM_RSA_X_509), but the
          documentation (/* = Raw.  NOT CKM_RSA_PKCS;*/) did not give a reason for this.
          Since CKM_SHA256_RSA_PKCS works fine with SoftHSM2, I did not put time into
          implementing PKCS#1 1.5 padding again here, but if this is needed the data
          structure is shown in e.g. RFC8017, A.2.4. RSASSA-PKCS-v1_5.
    """
    logger.debug(f'Signing {len(data)} bytes with key {key}')
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
    sig = key.session.sign(key.private_key[0], data, mechanism)
    sig_b = bytes(sig)
    return base64.b64encode(sig_b)


KSKM_P11 = NewType('KSKM_P11', List[KSKM_P11Module])


def init_pkcs11_modules_from_dict(config: dict) -> KSKM_P11:
    """
    Initialize PKCS#11 modules using configuration dictionary.

    :return: A list of PyKCS11 library instances.
    """
    modules: list = []
    for label, kwargs in config.items():
        modules.append(KSKM_P11Module(label=label, **kwargs))

    return KSKM_P11(modules)


def init_pkcs11_modules(config_dir: str) -> KSKM_P11:
    """
    Parse *.hsmconfig files in the config_dir and initialize PKCS#11 modules accordingly.

    :return: A list of PyKCS11 library instances.
    """
    modules: list = []
    for fn in glob.glob(os.path.join(config_dir, '*.hsmconfig')):
        if not os.path.isfile(fn):
            continue
        logger.debug('Loading HSM configuration file {}'.format(fn))
        env = load_hsmconfig(fn)
        logger.debug('Parsed configuration: {!r}'.format(env))
        # Save old values from the environment so we can reset it between modules
        old_env = {}
        for key in env.keys():
            old_env[key] = os.environ.get(key)
        os.environ.update(env)

        lib = KSKM_P11Module(env['PKCS11_LIBRARY_PATH'])
        modules += [lib]

        # reset environment
        for k, v in old_env.items():
            if v is None:
                del(os.environ[k])
            else:
                os.environ[k] = v
    return KSKM_P11(modules)


def load_hsmconfig(fn: str, defaults: Optional[MutableMapping] = None, max_lines: int = 100) -> dict:
    """
    Load a .hsmconfig file, and perform variable interpolation.

    Example `keyper.hsmconfig' file contents:

        KEYPER_LIBRARY_PATH=$HOME/dnssec/ksr/AEP
        LD_LIBRARY_PATH=$KEYPER_LIBRARY_PATH
        PKCS11_LIBRARY_PATH=$KEYPER_LIBRARY_PATH/pkcs11.GCC4.0.2.so.4.07

    If the `defaults' dictionary is empty, $HOME will be expanded from the OS environment,
    and KEYPER_LIBRARY_PATH on line two and three will be expanded from line 1.
    """
    if not defaults:
        defaults = os.environ
    with open(fn) as fd:
        res = parse_hsmconfig(fd, fn, defaults, max_lines)
    if 'PKCS11_LIBRARY_PATH' not in res:
        raise RuntimeError('PKCS11_LIBRARY_PATH not set in HSM config {}'.format(fn))
    return res


def parse_hsmconfig(config: Iterator, src: str, defaults: MutableMapping, max_lines: int = 100) -> dict:
    """
    Parse configuration data and perform variable interpolation.

    The variable interpolation will use the provided defaults if a variable does not
    refer to something already seen in the config.

    This function does not update the environment in order to be side-effect free
    (and thus more easier to test and verify).

    :return: A dict to update os.environ with.
    """
    res: Dict[str, str] = {}
    for line in config:
        max_lines -= 1
        if not max_lines:
            raise RuntimeError('HSM config source {} too long'.format(src))
        # Skip comments (line starting with (optional) whitespace and then '#') and empty lines
        line = line.strip().strip('\n')
        if not line or line.startswith('#'):
            continue
        try:
            separator_idx = line.index('=')
        except ValueError:
            raise ValueError('Badly formed line {!r} in HSM config {}'.format(line, src))
        lhs = line[:separator_idx]
        rhs = line[separator_idx + 1:]

        # Look for variables to interpolate (regexp matches patterns like $VAR or $FOO_BAR).
        while True:
            m = re.search(r'\$(\w+)', rhs)
            if not m:
                break
            key = m.group(1)
            val = res.get(key, defaults.get(key))
            if not val:
                raise RuntimeError('Failed interpolating variable ${} in HSM config {}: not set'.format(
                    key, src
                ))
            if '$' in val:
                raise ValueError('Variable interpolation of {} in HSM config {} to new variable '
                                 '({}) is not allowed'.format(key, src, val))
            rhs = rhs.replace('${}'.format(key), val)
        res[lhs] = rhs
    return res


def get_p11_key(label: str, p11modules: KSKM_P11, public: bool) -> Optional[KSKM_P11Key]:
    """
    Look for a key with CKA_LABEL matching 'label'.

    Iterates through all the available PKCS#11 modules, and returns a reference to the
    first key found with the right label. The parameter 'public' determines if the search
    should be for a public or private key object.

    :param label: CKA_LABEL to look for
    :param p11modules: The list of PKCS#11 modules
    :param public: Try to locate a public/private key
    :return: None or a PKCS#11 key object reference
    """
    for module in p11modules:
        p11key = module.find_key_by_label(label, public=public)
        if p11key is not None:
            return p11key
    return None
