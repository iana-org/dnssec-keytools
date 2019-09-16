"""Hardware Security Module interface functions."""
from __future__ import annotations

import binascii
import glob
import logging
import os
import re
from copy import copy
from dataclasses import dataclass, field
from enum import Enum
from getpass import getpass
from hashlib import sha1, sha256, sha384, sha512
from typing import (Any, Dict, Iterator, List, Mapping, MutableMapping,
                    NewType, Optional, Tuple)

import PyKCS11
from PyKCS11.LowLevel import CKF_RW_SESSION, CKU_SO, CKU_USER

from kskm.common.data import AlgorithmDNSSEC
from kskm.common.ecdsa_utils import KSKM_PublicKey_ECDSA
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import KSKM_PublicKey_RSA

__author__ = 'ft'


logger = logging.getLogger(__name__)


class KeyClass(Enum):
    """Re-representation of PKCS#11 key classes to shield other modules from the details."""
    PUBLIC = PyKCS11.LowLevel.CKO_PUBLIC_KEY
    PRIVATE = PyKCS11.LowLevel.CKO_PRIVATE_KEY
    SECRET = PyKCS11.LowLevel.CKO_SECRET_KEY


class KeyType(Enum):
    RSA = PyKCS11.LowLevel.CKK_RSA
    EC = PyKCS11.LowLevel.CKK_EC
    AES = PyKCS11.LowLevel.CKK_AES
    DES3 = PyKCS11.LowLevel.CKK_DES3


@dataclass
class KeyInfo(object):
    """
    Inventory information about a key found in a slot.
    """
    key_class: KeyClass
    key_id: Tuple[int]
    label: str
    p11key: Optional[KSKM_P11Key] = field(repr=False, default=None)
    pubkey: Optional[KSKM_PublicKey] = field(repr=False, default=None)


class WrappingAlgorithm(Enum):
    AES256 = 'AES256'
    DES3 = '3DES'  # 3DES is an invalid token in Python


@dataclass
class KSKM_P11Key(object):
    """A reference to a key object loaded from a PKCS#11 module."""

    label: str  # for debugging
    key_type: KeyType
    key_class: KeyClass
    public_key: Optional[KSKM_PublicKey]
    session: Any = field(repr=False)  # PyKCS11 opaque data
    privkey_handle: Optional[List[PyKCS11.CK_OBJECT_HANDLE]] = field(repr=False, default=None)  # PyKCS11 opaque data
    pubkey_handle: Optional[List[PyKCS11.CK_OBJECT_HANDLE]] = field(repr=False, default=None)  # PyKCS11 opaque data

    def __str__(self) -> str:
        s = f'key_label={self.label}'
        if self.public_key:
            s += ' ' + str(self.public_key)
        return s

    def key_wrap_mechanism(self) -> PyKCS11.Mechanism:
        """Get key wrap mechanism for this key."""
        if self.key_type == KeyType.AES:
            return PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_AES_KEY_WRAP, None)
        elif self.key_type == KeyType.DES3:
            return PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_DES3_ECB, None)
        else:
            raise RuntimeError(f'Don\'t know a wrapping mechanism for key type {self.key_type}')

    def key_wrap_algorithm(self) -> WrappingAlgorithm:
        """Get key wrap algorithm for this key."""
        if self.key_type == KeyType.AES:
            return WrappingAlgorithm.AES256
        elif self.key_type == KeyType.DES3:
            return WrappingAlgorithm.DES3
        else:
            raise RuntimeError(f'Don\'t know a wrapping algorithm for key type {self.key_type}')


class KSKM_P11Module(object):
    """KSKM interface to a PKCS#11 module."""

    def __init__(self, module: str, label: Optional[str] = None,
                 pin: Optional[str] = None, so_pin: Optional[str] = None,
                 so_login: bool = False, rw_session: bool = False,
                 env: Optional[Dict[str, str]] = None):
        """Load and initialise a PKCS#11 module.
        :param so_login: Log in as SO or USER
        :param rw_session: Request a R/W session or not
        """
        if module.startswith('$'):
            self.module = os.environ.get(module.lstrip('$'))
        else:
            self.module = module

        # Parameters affecting login to slots
        self._so_login = so_login
        self._rw_session = rw_session

        if label is None:
            self.label = module
        else:
            self.label = label

        logger.info(f'Initializing PKCS#11 module {self.label} using {self.module}')

        # configure environment
        old_env = {}
        if env:
            for key in env.keys():
                old_env[key] = os.environ.get(key)
            os.environ.update(env)

        # load module
        self._lib = PyKCS11.PyKCS11Lib()
        self._lib.load(self.module)
        self._lib.lib.C_Initialize()

        # reset environment
        if env:
            for k, v in old_env.items():
                if v is None:
                    del(os.environ[k])
                else:
                    os.environ[k] = v

        # set PIN
        self.pin = None
        if pin is None:
            if not so_login:
                self.pin = getpass(f"Enter USER PIN for PKCS#11 module {self.label}: ")
        else:
            self.pin = str(pin)

        self.so_pin = None
        if so_pin is None:
            if so_login:
                self.so_pin = getpass(f"Enter SO PIN for PKCS#11 module {self.label}: ")
        else:
            self.so_pin = str(pin)

        # Mapping from slot number to session
        self._sessions: Dict[int, Any] = {}

        self._slots: List[int] = self._lib.getSlotList(tokenPresent=True)
        logger.debug(f'P11 slots: {self._slots}')
        if self._slots:
            # Need to log in for the AEP keyper to show a serial number
            _ = self.sessions
            _info = self._lib.getTokenInfo(self._slots[0])
            if _info:
                info = _info.to_dict()
                logger.info(f'HSM First slot:      {info.get("label")}')
                logger.info(f'HSM ManufacturerID:  {info.get("manufacturerID")}')
                logger.info(f'HSM Model:           {info.get("model")}')
                logger.info(f'HSM Serial:          {info.get("serialNumber")}')

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: {self.label} ({self.module})>'

    def close(self) -> None:
        """Close all sessions."""
        for slot in self._slots:
            self._lib.closeAllSessions(slot)
        self._sessions = {}

    @property
    def slots(self) -> List[int]:
        return self._slots

    @property
    def sessions(self) -> Mapping[int, PyKCS11.Session]:
        """Get sessions for all slots."""
        if not self._sessions:
            _success_count = 0
            for _slot in self._slots:
                try:
                    logger.debug(f'Opening slot {_slot} in module {self.label} '
                                 f'(R/W: {self._rw_session}, SO: {self._so_login})')
                    _user_type = CKU_SO if self._so_login else CKU_USER
                    _pin = self.so_pin if self._so_login else self.pin
                    _rw = CKF_RW_SESSION if self._rw_session else 0
                    _session = self._lib.openSession(_slot, flags=_rw)
                    if _pin is not None and len(_pin) > 0:
                        _session.login(_pin, user_type=_user_type)
                        logger.debug(f'Login to module {self.label} slot {_slot} successful')
                        _success_count += 1
                    else:
                        logger.warning(f'Not logging in to module {self.label} slot {_slot} - no PIN provided')
                    self._sessions[_slot] = _session
                except PyKCS11.PyKCS11Error:
                    if not _success_count:
                        _level = logging.WARNING
                    else:
                        # not an error if one or more slots succeeded before this one
                        _level = logging.DEBUG
                    logger.log(_level, f'Login to module {self.label} slot {_slot} failed')
                    self._slots = [x for x in self._slots if x != _slot]

        return self._sessions

    def find_key_by_label(self, label: str, key_class: KeyClass) -> Optional[KSKM_P11Key]:
        """
        Query the PKCS#11 module for a key with CKA_LABEL matching 'label'.
        """
        _slots: list = []
        for _slot, _session in self.sessions.items():
            template = [(PyKCS11.LowLevel.CKA_LABEL, label),
                        (PyKCS11.LowLevel.CKA_CLASS, key_class.value)]
            _slots += [_slot]
            res = _session.findObjects(template)
            if res:
                if len(res) > 1:
                    logger.warning(f'More than one ({len(res)}) keys with label {repr(label)} found in slot {_slot}')
                # logger.debug(f'Found key with label {label!r} in slot {_slot}')
                _pubkey = None
                _pubkey_handle = None
                if key_class != KeyClass.SECRET:
                    _pubkey = self._p11_object_to_public_key(_session, res[0])
                    _pubkey_handle = res
                _cka_type = _session.getAttributeValue(res[0], [PyKCS11.LowLevel.CKA_KEY_TYPE])[0]
                key = KSKM_P11Key(label=label,
                                  key_type=KeyType(_cka_type),
                                  key_class=key_class,
                                  public_key=_pubkey,
                                  session=_session,
                                  privkey_handle=res if key_class != KeyClass.PUBLIC else None,
                                  pubkey_handle=_pubkey_handle
                                  )
                return key

        logger.debug(f'Key with label {label!r} not found in slots {_slots} (module {self.module})')
        return None

    def find_key_by_id(self, key_id: int, session: Any) -> List[KSKM_P11Key]:
        """
        Query the PKCS#11 module for a key with CKA_ID matching 'key_id'.
        """
        template = [(PyKCS11.LowLevel.CKA_ID, key_id)]
        res: List[KSKM_P11Key] = []
        objs = session.findObjects(template)
        for this in objs:
            key_class, label = session.getAttributeValue(this, [PyKCS11.LowLevel.CKA_CLASS,
                                                                PyKCS11.LowLevel.CKA_LABEL,
                                                                ])
            if key_class in [PyKCS11.LowLevel.CKO_PRIVATE_KEY,
                             PyKCS11.LowLevel.CKO_PUBLIC_KEY]:
                _cka_type = session.getAttributeValue(this, [PyKCS11.LowLevel.CKA_KEY_TYPE])[0]
                key = KSKM_P11Key(label=label,
                                  key_type=KeyType(_cka_type),
                                  key_class=KeyClass(key_class),
                                  public_key=self._p11_object_to_public_key(session, this),
                                  privkey_handle=this if key_class == PyKCS11.LowLevel.CKO_PRIVATE_KEY else None,
                                  pubkey_handle=this if key_class == PyKCS11.LowLevel.CKO_PUBLIC_KEY else None,
                                  session=session,
                                  )
                res += [key]
        return res

    def get_key_inventory(self, session: PyKCS11.Session) -> List[KeyInfo]:
        """Enumerate all keys found in a slot."""
        res: List[KeyInfo] = []

        for this in session.findObjects([]):
            cls, label, key_id = session.getAttributeValue(this, [PyKCS11.LowLevel.CKA_CLASS,
                                                                  PyKCS11.LowLevel.CKA_LABEL,
                                                                  PyKCS11.LowLevel.CKA_ID,
                                                                  ])
            logger.debug(f'Found key of class {cls}, label {label} and id {key_id}')
            if len(key_id) == 1:  # CKA_ID is represented as a tuple like (7,)
                key_id = key_id[0]

            if cls == PyKCS11.LowLevel.CKO_SECRET_KEY:
                res += [KeyInfo(key_class=KeyClass.SECRET, label=label, key_id=key_id)]
            elif cls == PyKCS11.LowLevel.CKO_PUBLIC_KEY:
                pub = self._p11_object_to_public_key(session, this)
                res += [KeyInfo(key_class=KeyClass.PUBLIC, label=label, key_id=key_id, p11key=this, pubkey=pub)]
            elif cls == PyKCS11.LowLevel.CKO_PRIVATE_KEY:
                res += [KeyInfo(key_class=KeyClass.PRIVATE, label=label, key_id=key_id, p11key=this)]

        return res

    @staticmethod
    def _p11_object_to_public_key(session: Any, data: Any) -> Optional[KSKM_PublicKey]:
        """Create an RSAPublicKeyData object from PKCS#11 findObject return data."""
        _cka_type = session.getAttributeValue(data, [PyKCS11.LowLevel.CKA_KEY_TYPE])[0]
        if _cka_type == PyKCS11.LowLevel.CKK_RSA:
            _modulus = session.getAttributeValue(data, [PyKCS11.LowLevel.CKA_MODULUS])
            _exp = session.getAttributeValue(data, [PyKCS11.LowLevel.CKA_PUBLIC_EXPONENT])
            rsa_e = int.from_bytes(bytes(_exp[0]), byteorder='big')
            rsa_n = bytes(_modulus[0])
            return KSKM_PublicKey_RSA(bits=len(rsa_n) * 8,
                                      exponent=rsa_e,
                                      n=rsa_n)
        elif _cka_type == PyKCS11.LowLevel.CKK_EC:
            # DER-encoding of ANSI X9.62 ECPoint value ''Q''.
            _cka_ec_point = session.getAttributeValue(data, [PyKCS11.LowLevel.CKA_EC_POINT])
            if not _cka_ec_point[0]:
                return None
            ec_point = bytes(_cka_ec_point[0])
            # SoftHSM2 tacks on an extra 0x04 <len-byte> before the 0x04 that signals an
            # uncompressed EC point. Check for that and remove it if found.
            _prefix = bytes([4, len(ec_point) - 2, 4])
            if ec_point.startswith(_prefix):
                ec_point = ec_point[2:]
            ec_params = bytes(session.getAttributeValue(data, [PyKCS11.LowLevel.CKA_EC_PARAMS])[0])
            logger.debug(f'EC_POINT: {binascii.hexlify(ec_point)}')
            logger.debug(f'EC_PARAMS: {binascii.hexlify(ec_params)}')
            # ec_point is an 0x04 prefix byte, and then both x and y points concatenated, so divide by 2
            _ec_len = (len(ec_point) - 1) * 8 // 2
            # TODO: Get algorithm from EC_PARAMS (contains an OID) instead of guessing based on len
            if _ec_len == 256:
                alg = AlgorithmDNSSEC.ECDSAP256SHA256
            elif _ec_len == 384:
                alg = AlgorithmDNSSEC.ECDSAP384SHA384
            else:
                raise RuntimeError(f'Unexpected ECDSA key length: {_ec_len}')
            return KSKM_PublicKey_ECDSA(bits=_ec_len, q=ec_point, algorithm=alg)
        else:
            raise NotImplementedError('Unknown CKA_TYPE: {}'.format(PyKCS11.CKK[_cka_type]))


def sign_using_p11(key: KSKM_P11Key, data: bytes, algorithm: AlgorithmDNSSEC) -> bytes:
    """Sign some data using a PKCS#11 key."""
    # Mechanism CKM_ECDSA is without hashing, so pre-hash data if using ECDSA
    if algorithm == AlgorithmDNSSEC.ECDSAP256SHA256:
        data = sha256(data).digest()
    elif algorithm == AlgorithmDNSSEC.ECDSAP384SHA384:
        data = sha384(data).digest()

    logger.debug(f'Signing {len(data)} bytes with key {key}, algorithm {algorithm.name}')
    # With SoftHSMv2, the following PKCS#11 mechanisms would be available,
    #
    #  {AlgorithmDNSSEC.RSASHA1: PyKCS11.LowLevel.CKM_SHA1_RSA_PKCS,
    #   AlgorithmDNSSEC.RSASHA256: PyKCS11.LowLevel.CKM_SHA256_RSA_PKCS,
    #   AlgorithmDNSSEC.RSASHA512: PyKCS11.LowLevel.CKM_SHA512_RSA_PKCS,
    #  }
    #
    # but not with the AEP Keyper, so we implement RSA PKCS#1 1.5 padding ourselves here
    # and instead use the 'raw' RSA signing mechanism CKM_RSA_X_509.
    mechanism = {AlgorithmDNSSEC.RSASHA1: PyKCS11.LowLevel.CKM_RSA_X_509,
                 AlgorithmDNSSEC.RSASHA256: PyKCS11.LowLevel.CKM_RSA_X_509,
                 AlgorithmDNSSEC.RSASHA512: PyKCS11.LowLevel.CKM_RSA_X_509,
                 AlgorithmDNSSEC.ECDSAP256SHA256: PyKCS11.LowLevel.CKM_ECDSA,
                 AlgorithmDNSSEC.ECDSAP384SHA384: PyKCS11.LowLevel.CKM_ECDSA,
                 }.get(algorithm)
    if mechanism is None:
        raise RuntimeError(f'Can\'t PKCS#11 sign data with algorithm {algorithm.name}')

    if mechanism == PyKCS11.LowLevel.CKM_RSA_X_509:
        # Pad according to RFC3447  9.2 EMSA-PKCS1-v1_5
        if algorithm == AlgorithmDNSSEC.RSASHA1:
            digest = sha1(data).digest()
            oid = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
        elif algorithm == AlgorithmDNSSEC.RSASHA256:
            digest = sha256(data).digest()
            oid = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
        elif algorithm == AlgorithmDNSSEC.RSASHA512:
            digest = sha512(data).digest()
            oid = b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'
        else:
            raise RuntimeError(f'Don\'t know how to pad algorithm {algorithm}')
        if not isinstance(key.public_key, KSKM_PublicKey_RSA):
            raise ValueError(f'Can\'t RSA sign with non-RSA key {key}')
        T = oid + digest
        sig_len = key.public_key.bits // 8
        pad_len = sig_len - len(T) - 3
        pad = b'\xff' * pad_len
        data = bytes([0x0, 0x1]) + pad + b'\x00' + T

    if not key.privkey_handle:
        raise RuntimeError(f'No private key supplied in {key}')
    sig = key.session.sign(key.privkey_handle[0], data, PyKCS11.Mechanism(mechanism, None))
    return bytes(sig)


KSKM_P11 = NewType('KSKM_P11', List[KSKM_P11Module])


def init_pkcs11_modules_from_dict(config: Mapping, so_login: bool = False,
                                  rw_session: bool = False) -> KSKM_P11:
    """
    Initialize PKCS#11 modules using configuration dictionary.

    :return: A list of PyKCS11 library instances.
    """
    modules: list = []
    for label, _kwargs in config.items():
        kwargs = copy(_kwargs)  # don't modify caller's data
        if so_login:
            kwargs['so_login'] = True
        if rw_session:
            kwargs['rw_session'] = rw_session
        modules.append(KSKM_P11Module(label=label, **kwargs))

    return KSKM_P11(modules)


def init_pkcs11_modules(config_dir: str, so_login: bool = False) -> KSKM_P11:
    """
    Parse *.hsmconfig files in the config_dir and initialize PKCS#11 modules accordingly.

    :param so_login: Login as PKCS#11 Security Officer, otherwise login as ordinary user
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

        lib = KSKM_P11Module(env['PKCS11_LIBRARY_PATH'], so_login=so_login)
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
    key_class = KeyClass.PUBLIC if public else KeyClass.PRIVATE
    for module in p11modules:
        p11key = module.find_key_by_label(label, key_class)
        if p11key is not None:
            return p11key
    return None


def get_p11_secret_key(label: str, p11modules: KSKM_P11) -> Optional[KSKM_P11Key]:
    """
    Look for a secret key (wrapping key) with CKA_LABEL matching 'label'.

    Iterates through all the available PKCS#11 modules, and returns a reference to the
    first key found with the right label.

    :param label: CKA_LABEL to look for
    :param p11modules: The list of PKCS#11 modules
    :return: None or a PKCS#11 key object reference
    """
    for module in p11modules:
        p11key = module.find_key_by_label(label, key_class=KeyClass.SECRET)
        if p11key is not None:
            return p11key
    return None
