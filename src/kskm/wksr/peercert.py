"""Peer certificate functions."""

from binascii import hexlify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate, load_der_x509_certificate
from fastapi import Request


def request_peercert(request: Request) -> Certificate:
    cert = (
        request.scope["transport"]
        .get_extra_info("ssl_object")
        .getpeercert(binary_form=True)
    )
    return load_der_x509_certificate(cert)


def request_peercert_client_subject(request: Request) -> str | None:
    if peercert := request_peercert(request):
        return "/".join([attr.rfc4514_string() for attr in peercert.subject.rdns])


def request_peercert_digest(request: Request) -> str | None:
    if peercert := request_peercert(request):
        return hexlify(peercert.fingerprint(hashes.SHA256())).decode()


def request_peercert_digest_spki(request: Request) -> str | None:
    if peercert := request_peercert(request):
        public_key_der = peercert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_key_der)
        return hexlify(digest.finalize()).decode()
