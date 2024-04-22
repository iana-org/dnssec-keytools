"""Hardware Security Module interface functions."""

from __future__ import annotations

import binascii
import logging
import os
import re
from collections.abc import Iterator, Mapping, MutableMapping
from dataclasses import field
from enum import Enum
from getpass import getpass
from hashlib import sha1, sha256, sha384, sha512
from pathlib import Path
from typing import Any, NewType, Self

import PyKCS11
import PyKCS11.LowLevel
from pydantic import BaseModel, ConfigDict

from kskm.common.config import KSKMConfig
from kskm.common.config_misc import KSKMHSM
from kskm.common.data import AlgorithmDNSSEC, FrozenBaseModel
from kskm.common.ecdsa_utils import ECCurve, KSKM_PublicKey_ECDSA
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import KSKM_PublicKey_RSA

__author__ = "ft"


logger = logging.getLogger(__name__)


P11_CKA_Constant = NewType("P11_CKA_Constant", int)
P11_CKF_Constant = NewType("P11_CKF_Constant", int)
P11_CKK_Constant = NewType("P11_CKK_Constant", int)
P11_CKM_Constant = NewType("P11_CKM_Constant", int)
P11_CKO_Constant = NewType("P11_CKO_Constant", int)
P11_CKU_Constant = NewType("P11_CKU_Constant", int)


class PyKCS11WithTypes(BaseModel):
    """Get all the constants we use, with type information."""

    model_config = ConfigDict(extra="ignore")

    CKA_CLASS: P11_CKA_Constant
    CKA_EC_PARAMS: P11_CKA_Constant
    CKA_EC_POINT: P11_CKA_Constant
    CKA_ID: P11_CKA_Constant
    CKA_KEY_TYPE: P11_CKA_Constant
    CKA_LABEL: P11_CKA_Constant
    CKA_MODULUS: P11_CKA_Constant
    CKA_PUBLIC_EXPONENT: P11_CKA_Constant

    CKF_RW_SESSION: P11_CKF_Constant

    CKK_AES: P11_CKK_Constant
    CKK_DES3: P11_CKK_Constant
    CKK_EC: P11_CKK_Constant
    CKK_RSA: P11_CKK_Constant

    CKM_ECDSA: P11_CKM_Constant
    CKM_ECDSA_SHA256: P11_CKM_Constant
    CKM_ECDSA_SHA384: P11_CKM_Constant
    CKM_RSA_X_509: P11_CKM_Constant
    CKM_SHA1_RSA_PKCS: P11_CKM_Constant
    CKM_SHA256_RSA_PKCS: P11_CKM_Constant
    CKM_SHA512_RSA_PKCS: P11_CKM_Constant

    CKO_PRIVATE_KEY: P11_CKO_Constant
    CKO_PUBLIC_KEY: P11_CKO_Constant
    CKO_SECRET_KEY: P11_CKO_Constant

    CKU_SO: P11_CKU_Constant
    CKU_USER: P11_CKU_Constant

    def findObjects(
        self, session: PyKCS11.Session, template: list[tuple[Any, Any]]
    ) -> list[PyKCS11.LowLevel.CK_OBJECT_HANDLE]:
        """Helper function to get proper typing."""
        return session.findObjects(template)  # type: ignore[no-any-return]

    def getAttributeValue(
        self,
        session: PyKCS11.Session,
        obj: PyKCS11.LowLevel.CK_OBJECT_HANDLE,
        attrs: list[int],
    ) -> list[Any]:
        """Helper function to get proper typing."""
        return session.getAttributeValue(obj, attrs)  # type: ignore[no-any-return]


_p11 = PyKCS11WithTypes.model_validate(PyKCS11.LowLevel.__dict__)


class KeyClass(Enum):
    """Re-representation of PKCS#11 key classes to shield other modules from the details."""

    PUBLIC = _p11.CKO_PUBLIC_KEY
    PRIVATE = _p11.CKO_PRIVATE_KEY
    SECRET = _p11.CKO_SECRET_KEY


class KeyType(Enum):
    """Re-representation of PKCS#11 key types classes to shield other modules from the details."""

    RSA = _p11.CKK_RSA
    EC = _p11.CKK_EC
    AES = _p11.CKK_AES
    DES3 = _p11.CKK_DES3


class KeyInfo(FrozenBaseModel):
    """Inventory information about a key found in a slot."""

    key_class: KeyClass
    key_id: tuple[int]
    label: str
    pubkey: KSKM_PublicKey | None = field(repr=False, default=None)


class KSKM_P11Key(BaseModel):
    """A reference to a key object loaded from a PKCS#11 module."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    label: str  # for debugging
    key_type: KeyType
    key_class: KeyClass
    hash_using_hsm: bool | None = None
    public_key: KSKM_PublicKey | None
    session: Any = field(default=None, repr=False)  # PyKCS11 opaque data
    privkey_handle: PyKCS11.LowLevel.CK_OBJECT_HANDLE | None = field(
        repr=False, default=None
    )  # PyKCS11 opaque data
    pubkey_handle: PyKCS11.LowLevel.CK_OBJECT_HANDLE | None = field(
        repr=False, default=None
    )  # PyKCS11 opaque data

    def __str__(self) -> str:
        """Return string."""
        ret = f"key_label={self.label}"
        if self.public_key:
            ret += " " + str(self.public_key)
        return ret

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return self.model_copy(update=kwargs)


class KSKM_P11Module:
    """KSKM interface to a PKCS#11 module."""

    def __init__(
        self,
        label: str,
        hsm: KSKMHSM,
        so_login: bool,
        rw_session: bool,
    ):
        """
        Load and initialise a PKCS#11 module.

        :param so_login: Log in as SO or USER
        :param rw_session: Request a R/W session or not
        """
        self.module: Path | str
        if isinstance(hsm.module, str) and hsm.module.startswith("$"):
            if not (_module := os.environ.get(hsm.module.lstrip("$"))):
                raise RuntimeError(f"Environment variable {hsm.module} not set")
            self.module = Path(_module)
        else:
            self.module = hsm.module

        # Parameters affecting login to slots
        self._so_login = so_login
        self._rw_session = rw_session

        self.label = label

        logger.info(f"Initializing PKCS#11 module {self.label} using {self.module}")

        # configure environment
        old_env: dict[str, Any] = {}
        if hsm.env:
            for key in hsm.env:
                old_env[key] = os.environ.get(key)
            os.environ.update(hsm.env)

        # load module
        self._lib = PyKCS11.PyKCS11Lib()
        self._lib.load(str(self.module))  # type: ignore[unused-ignore]
        self._lib.lib.C_Initialize()

        # reset environment
        if hsm.env:
            for key, val in old_env.items():
                if val is None:
                    del os.environ[key]
                else:
                    os.environ[key] = val

        # set PIN
        self.pin = None
        if hsm.pin is None:
            if not so_login:
                self.pin = getpass(f"Enter USER PIN for PKCS#11 module {self.label}: ")
        else:
            self.pin = str(hsm.pin)

        self.so_pin = None
        if hsm.so_pin is None:
            if so_login:
                self.so_pin = getpass(f"Enter SO PIN for PKCS#11 module {self.label}: ")
        else:
            self.so_pin = str(hsm.pin)

        # Mapping from slot number to session
        self._sessions: dict[int, Any] = {}

        self._slots: list[int] = self._lib.getSlotList(tokenPresent=True)

        self.show_information()

    def show_information(self) -> None:
        """Show HSM information."""
        logger.debug(f"P11 slots: {self._slots}")
        if self._slots:
            # Need to log in for the AEP keyper to show a serial number
            _ = self.sessions
            _info = self._lib.getTokenInfo(self._slots[0])  # type: ignore[unused-ignore]
            if _info:
                info: Mapping[str, str] = _info.to_dict()
                logger.info(f'HSM First slot:      {info.get("label")}')
                logger.info(f'HSM ManufacturerID:  {info.get("manufacturerID")}')
                logger.info(f'HSM Model:           {info.get("model")}')
                logger.info(f'HSM Serial:          {info.get("serialNumber")}')
        else:
            logger.warning("No slots found in HSM")

    def __str__(self) -> str:
        """Return P11 module as string."""
        return f"<{self.__class__.__name__}: {self.label} ({self.module})>"

    def close(self) -> None:
        """Close all sessions."""
        for slot in self._slots:
            self._lib.closeAllSessions(slot)  # type: ignore[unused-ignore]
        self._sessions = {}

    @property
    def slots(self) -> list[int]:
        """Return all slots."""
        return self._slots

    @property
    def sessions(self) -> Mapping[int, PyKCS11.Session]:
        """Get sessions for all slots."""
        if not self._sessions:
            _success_count = 0
            for _slot in self._slots:
                try:
                    logger.debug(
                        f"Opening slot {_slot} in module {self.label} "
                        f"(R/W: {self._rw_session}, SO: {self._so_login})"
                    )
                    _user_type = _p11.CKU_SO if self._so_login else _p11.CKU_USER
                    _pin = self.so_pin if self._so_login else self.pin
                    _rw = _p11.CKF_RW_SESSION if self._rw_session else 0
                    _session = self._lib.openSession(_slot, flags=_rw)  # type: ignore[unused-ignore]
                    if _pin is not None and len(_pin) > 0:
                        _session.login(_pin, user_type=_user_type)  # type: ignore[unused-ignore]
                        logger.debug(
                            f"Login to module {self.label} slot {_slot} successful"
                        )
                        _success_count += 1
                    else:
                        logger.warning(
                            f"Not logging in to module {self.label} slot {_slot} - no PIN provided"
                        )
                    self._sessions[_slot] = _session
                except PyKCS11.PyKCS11Error:
                    # not an error if one or more slots succeeded before this one
                    _level = logging.WARNING if not _success_count else logging.DEBUG
                    logger.log(
                        _level, f"Login to module {self.label} slot {_slot} failed"
                    )
                    self._slots = [x for x in self._slots if x != _slot]

        return self._sessions

    def find_key_by_label(
        self, label: str, key_class: KeyClass, hash_using_hsm: bool | None = None
    ) -> KSKM_P11Key | None:
        """Query the PKCS#11 module for a key with CKA_LABEL matching 'label'."""
        _slots: list[int] = []
        for _slot, _session in self.sessions.items():
            template: list[tuple[Any, Any]] = [
                (_p11.CKA_LABEL, label),
                (_p11.CKA_CLASS, key_class.value),
            ]
            _slots += [_slot]
            res = _p11.findObjects(_session, template)
            if res:
                if len(res) > 1:
                    raise RuntimeError(
                        f"More than one ({len(res)}) keys with label {repr(label)} found in slot {_slot}"
                    )
                # logger.debug(f'Found key with label {label!r} in slot {_slot}')
                this = res[0]
                _pubkey = None
                _pubkey_handle: PyKCS11.LowLevel.CK_OBJECT_HANDLE | None = None
                if key_class != KeyClass.SECRET:
                    _pubkey = self._p11_object_to_public_key(_session, this)
                    _pubkey_handle = this
                _cka_type = _p11.getAttributeValue(_session, this, [_p11.CKA_KEY_TYPE])[
                    0
                ]
                key = KSKM_P11Key(
                    label=label,
                    key_type=KeyType(_cka_type),
                    key_class=key_class,
                    hash_using_hsm=hash_using_hsm,
                    public_key=_pubkey,
                    session=_session,
                    privkey_handle=this if key_class != KeyClass.PUBLIC else None,
                    pubkey_handle=_pubkey_handle,
                )
                return key

        logger.debug(
            f"Key with label {label!r} not found in slots {_slots} (module {self.module})"
        )
        return None

    def find_key_by_id(
        self, key_id: tuple[int], session: PyKCS11.Session
    ) -> list[KSKM_P11Key]:
        """Query the PKCS#11 module for a key with CKA_ID matching 'key_id'."""
        template = [(_p11.CKA_ID, key_id)]
        res: list[KSKM_P11Key] = []
        objs = _p11.findObjects(session, template)
        for this in objs:
            key_class, label = _p11.getAttributeValue(
                session, this, [_p11.CKA_CLASS, _p11.CKA_LABEL]
            )
            if key_class in [
                _p11.CKO_PRIVATE_KEY,
                _p11.CKO_PUBLIC_KEY,
            ]:
                _cka_type = _p11.getAttributeValue(session, this, [_p11.CKA_KEY_TYPE])[
                    0
                ]
                key = KSKM_P11Key(
                    label=label,
                    key_type=KeyType(_cka_type),
                    key_class=KeyClass(key_class),
                    public_key=self._p11_object_to_public_key(session, this),
                    privkey_handle=(
                        this if key_class == _p11.CKO_PRIVATE_KEY else None
                    ),
                    pubkey_handle=(this if key_class == _p11.CKO_PUBLIC_KEY else None),
                    session=session,
                )
                res += [key]
        return res

    def get_key_inventory(self, session: PyKCS11.Session) -> list[KeyInfo]:
        """Enumerate all keys found in a slot."""
        res: list[KeyInfo] = []

        for this in _p11.findObjects(session, []):
            cls, label, key_id = _p11.getAttributeValue(
                session,
                this,
                [
                    _p11.CKA_CLASS,
                    _p11.CKA_LABEL,
                    _p11.CKA_ID,
                ],
            )
            logger.debug(f"Found key of class {cls}, label {label} and id {key_id}")

            if cls == _p11.CKO_SECRET_KEY:
                res += [KeyInfo(key_class=KeyClass.SECRET, label=label, key_id=key_id)]
            elif cls == _p11.CKO_PUBLIC_KEY:
                pub = self._p11_object_to_public_key(session, this)
                res += [
                    KeyInfo(
                        key_class=KeyClass.PUBLIC,
                        label=label,
                        key_id=key_id,
                        pubkey=pub,
                    )
                ]
            elif cls == _p11.CKO_PRIVATE_KEY:
                res += [
                    KeyInfo(
                        key_class=KeyClass.PRIVATE,
                        label=label,
                        key_id=key_id,
                    )
                ]

        return res

    @staticmethod
    def _p11_object_to_public_key(
        session: PyKCS11.Session, data: Any
    ) -> KSKM_PublicKey | None:
        """Create an RSAPublicKeyData object from PKCS#11 findObject return data."""
        _cka_type = _p11.getAttributeValue(session, data, [_p11.CKA_KEY_TYPE])[0]
        if _cka_type == _p11.CKK_RSA:
            _modulus = _p11.getAttributeValue(session, data, [_p11.CKA_MODULUS])
            _exp = _p11.getAttributeValue(session, data, [_p11.CKA_PUBLIC_EXPONENT])
            rsa_e = int.from_bytes(bytes(_exp[0]), byteorder="big")
            rsa_n = bytes(_modulus[0])
            return KSKM_PublicKey_RSA(bits=len(rsa_n) * 8, exponent=rsa_e, n=rsa_n)
        if _cka_type == _p11.CKK_EC:
            # DER-encoding of ANSI X9.62 ECPoint value ''Q''.
            _cka_ec_point = _p11.getAttributeValue(session, data, [_p11.CKA_EC_POINT])
            if not _cka_ec_point[0]:
                return None
            ec_point = bytes(_cka_ec_point[0])
            # SoftHSM2 tacks on an extra 0x04 <len-byte> before the 0x04 that signals an
            # uncompressed EC point. Check for that and remove it if found.
            _prefix = bytes([4, len(ec_point) - 2, 4])
            if ec_point.startswith(_prefix):
                ec_point = ec_point[2:]
            logger.debug("EC_POINT: %s", binascii.hexlify(ec_point))
            ec_params = bytes(
                _p11.getAttributeValue(session, data, [_p11.CKA_EC_PARAMS])[0]
            )
            # The CKA_EC_PARAMS is an ASN.1 encoded OID. To not drag in an ASN.1 dependency,
            # we keep this lookup table of OIDs to algorithms.
            _ec_oid_to_curve = {
                # OID 1.2.840.10045.3.1.7 / prime256v1
                b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07": ECCurve.P256,
                # OID 1.3.132.0.34 / prime384v1
                b"\x06\x05\x2b\x81\x04\x00\x22": ECCurve.P384,
            }
            crv = _ec_oid_to_curve.get(ec_params)
            logger.debug(
                "EC_PARAMS: %s (algorithm %s)", binascii.hexlify(ec_params), crv
            )
            if not crv:
                raise RuntimeError("Unknown EC algorithm")
            # ec_point is an 0x04 prefix byte, and then both x and y points concatenated, so divide by 2
            _ec_len = (len(ec_point) - 1) * 8 // 2
            if (crv == ECCurve.P256 and _ec_len != 256) or (
                crv == ECCurve.P384 and _ec_len != 384
            ):
                raise RuntimeError(
                    f"Unexpected ECDSA key length {_ec_len} for curve {crv}"
                )
            return KSKM_PublicKey_ECDSA(bits=_ec_len, q=ec_point, curve=crv)
        raise NotImplementedError(f"Unknown CKA_TYPE: {_cka_type}")


def sign_using_p11(key: KSKM_P11Key, data: bytes, algorithm: AlgorithmDNSSEC) -> bytes:
    """Sign some data using a PKCS#11 key."""

    _sign_data = _format_data_for_signing(key, data, algorithm)

    logger.info(
        f"Signing {len(_sign_data.data)} bytes with key {key}, algorithm {algorithm.name}, " +
        f"mechanism {_sign_data.mechanism_name}, hash using hsm={_sign_data.hash_using_hsm}"
    )

    if not key.privkey_handle:
        raise RuntimeError(f"No private key supplied in {key}")
    sig = key.session.sign(
        key.privkey_handle,
        _sign_data.data,
        PyKCS11.Mechanism(_sign_data.mechanism, None),
    )
    return bytes(sig)


class DataToSign(BaseModel):
    """Hold the data to sign, formatted to suit the mechanism used."""

    data: bytes
    mechanism: P11_CKM_Constant
    hash_using_hsm: bool
    mechanism_name: str


def _format_data_for_signing(
    key: KSKM_P11Key, data: bytes, algorithm: AlgorithmDNSSEC
) -> DataToSign:
    mechanism: P11_CKM_Constant | None

    if key.hash_using_hsm:
        mechanism = {
            AlgorithmDNSSEC.RSASHA1: _p11.CKM_SHA1_RSA_PKCS,
            AlgorithmDNSSEC.RSASHA256: _p11.CKM_SHA256_RSA_PKCS,
            AlgorithmDNSSEC.RSASHA512: _p11.CKM_SHA512_RSA_PKCS,
            AlgorithmDNSSEC.ECDSAP256SHA256: _p11.CKM_ECDSA_SHA256,
            AlgorithmDNSSEC.ECDSAP384SHA384: _p11.CKM_ECDSA_SHA384,
        }.get(algorithm)
    else:
        # The AEP Keyper doesn't support hashing on the HSM, so we implement RSA PKCS#1 1.5 padding ourselves here
        mechanism = {
            AlgorithmDNSSEC.RSASHA1: _p11.CKM_RSA_X_509,
            AlgorithmDNSSEC.RSASHA256: _p11.CKM_RSA_X_509,
            AlgorithmDNSSEC.RSASHA512: _p11.CKM_RSA_X_509,
            AlgorithmDNSSEC.ECDSAP256SHA256: _p11.CKM_ECDSA,
            AlgorithmDNSSEC.ECDSAP384SHA384: _p11.CKM_ECDSA,
        }.get(algorithm)

    match mechanism:
        case (
            _p11.CKM_ECDSA_SHA256
            | _p11.CKM_ECDSA_SHA384
            | _p11.CKM_SHA1_RSA_PKCS
            | _p11.CKM_SHA256_RSA_PKCS
            | _p11.CKM_SHA512_RSA_PKCS
        ):
            # These mechanisms hash the data on the HSM
            pass
        case _p11.CKM_RSA_X_509:
            # The X.509 (raw) RSA mechanism does not hash the data on the HSM, so we need to hash it first.

            if not isinstance(key.public_key, KSKM_PublicKey_RSA):
                raise ValueError(f"Can't RSA sign with non-RSA key {key}")

            # Pad according to RFC3447  9.2 EMSA-PKCS1-v1_5
            if algorithm == AlgorithmDNSSEC.RSASHA1:
                digest = sha1(data).digest()
                oid = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
            elif algorithm == AlgorithmDNSSEC.RSASHA256:
                digest = sha256(data).digest()
                oid = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
            elif algorithm == AlgorithmDNSSEC.RSASHA512:
                digest = sha512(data).digest()
                oid = b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
            else:
                raise RuntimeError(f"Don't know how to pad algorithm {algorithm}")

            oid_digest = oid + digest
            sig_len = key.public_key.bits // 8
            pad_len = sig_len - len(oid_digest) - 3
            pad = b"\xff" * pad_len
            data = bytes([0x0, 0x1]) + pad + b"\x00" + oid_digest
        case _p11.CKM_ECDSA:
            # Mechanism CKM_ECDSA is without hashing, so pre-hash data if using ECDSA
            if algorithm == AlgorithmDNSSEC.ECDSAP256SHA256:
                data = sha256(data).digest()
            elif algorithm == AlgorithmDNSSEC.ECDSAP384SHA384:
                data = sha384(data).digest()
        case _:
            raise RuntimeError(
                f"Can't PKCS#11 sign data with algorithm {algorithm.name}"
            )

    _mechanism_name = str(PyKCS11.CKM[mechanism])  # type: ignore
    return DataToSign(
        data=data,
        mechanism=mechanism,
        hash_using_hsm=bool(key.hash_using_hsm),
        mechanism_name=_mechanism_name,
    )


KSKM_P11 = NewType("KSKM_P11", list[KSKM_P11Module])


def init_pkcs11_modules(
    config: KSKMConfig,
    name: str | None = None,
    so_login: bool = False,
    rw_session: bool = False,
) -> KSKM_P11:
    """
    Initialize PKCS#11 modules using configuration dictionary.

    If `name' is provided, _only_ the HSM matching that name is initialised.

    :return: A list of PyKCS11 library instances.
    """
    modules: list[KSKM_P11Module] = []
    for label, hsm in config.hsm.items():
        if name and label != name:
            continue
        modules.append(
            KSKM_P11Module(label, hsm, so_login=so_login, rw_session=rw_session)
        )

    if name and not modules:
        raise RuntimeError(f"No HSM with that name ({name}) found in the configuration")

    return KSKM_P11(modules)


def load_hsmconfig(
    filename: Path,
    defaults: MutableMapping[str, Any] | None = None,
    max_lines: int = 100,
) -> dict[str, Any]:
    """
    Load a .hsmconfig file, and perform variable interpolation.

    Example `keyper.hsmconfig' file contents:

        KEYPER_LIBRARY_PATH=$HOME/dnssec/ksr/AEP
        LD_LIBRARY_PATH=$KEYPER_LIBRARY_PATH
        PKCS11_LIBRARY_PATH=$KEYPER_LIBRARY_PATH/pkcs11.GCC4.0.2.so.4.07

    If the `defaults' dictionary is empty, $HOME will be expanded from the OS environment,
    and KEYPER_LIBRARY_PATH on line two and three will be expanded from line 1.
    """
    _defaults = defaults if defaults else os.environ
    with open(filename) as config_fd:
        res = parse_hsmconfig(config_fd, filename, _defaults, max_lines)
    if "PKCS11_LIBRARY_PATH" not in res:
        raise RuntimeError(f"PKCS11_LIBRARY_PATH not set in HSM config {filename}")
    return res


def parse_hsmconfig(
    config: Iterator[str],
    src: Path,
    defaults: MutableMapping[str, Any],
    max_lines: int = 100,
) -> dict[str, Any]:
    """
    Parse configuration data and perform variable interpolation.

    The variable interpolation will use the provided defaults if a variable does not
    refer to something already seen in the config.

    This function does not update the environment in order to be side-effect free
    (and thus more easier to test and verify).

    :return: A dict to update os.environ with.
    """
    res: dict[str, str] = {}
    for line in config:
        max_lines -= 1
        if not max_lines:
            raise RuntimeError(f"HSM config source {src} too long")
        # Skip comments (line starting with (optional) whitespace and then '#') and empty lines
        line = line.strip().strip("\n")
        if not line or line.startswith("#"):
            continue
        try:
            separator_idx = line.index("=")
        except ValueError as exc:
            raise ValueError(f"Badly formed line {line!r} in HSM config {src}") from exc
        lhs = line[:separator_idx]
        rhs = line[separator_idx + 1 :]

        # Look for variables to interpolate (regexp matches patterns like $VAR or $FOO_BAR).
        while True:
            match = re.search(r"\$(\w+)", rhs)
            if not match:
                break
            key = match.group(1)
            val = res.get(key, defaults.get(key))
            if not val:
                raise RuntimeError(
                    f"Failed interpolating variable ${key} in HSM config {src}: not set"
                )
            if "$" in val:
                raise ValueError(
                    f"Variable interpolation of {key} in HSM config {src} to new variable "
                    f"({val}) is not allowed"
                )
            rhs = rhs.replace(f"${key}", val)
        res[lhs] = rhs
    return res


def get_p11_key(
    label: str, p11modules: KSKM_P11, public: bool, hash_using_hsm: bool | None = None
) -> KSKM_P11Key | None:
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
        p11key = module.find_key_by_label(
            label, key_class, hash_using_hsm=hash_using_hsm
        )
        if p11key is not None:
            return p11key
    return None
