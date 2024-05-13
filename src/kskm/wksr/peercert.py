"""Peer certificate functions."""

from typing import Any

import OpenSSL
import OpenSSL.crypto
import werkzeug.serving
from flask import request


# TLS client auth based on post at https://www.ajg.id.au/2018/01/01/mutual-tls-with-python-flask-and-werkzeug/
class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """
    Client Certificate Authenticator.

    We subclass this class so that we can gain access to the connection
    property. self.connection is the underlying client socket. When a TLS
    connection is established, the underlying socket is an instance of
    SSLSocket, which in turn exposes the getpeercert() method.

    The output from that method is what we want to make available elsewhere
    in the application.
    """

    def make_environ(self) -> dict[str, Any]:
        """
        Create request environment.

        The superclass method develops the environ hash that eventually
        forms part of the Flask request object.

        We allow the superclass method to run first, then we insert the
        peer certificate into the hash. That exposes it to us later in
        the request variable that Flask provides
        """
        environ: dict[str, Any] = super().make_environ()
        try:
            x509_binary = self.connection.getpeercert(True)
        except (AttributeError, KeyError):
            # Not a TLS connection
            x509_binary = None
        if x509_binary is not None:
            x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, x509_binary
            )
            environ["peercert"] = x509
        return environ

    @classmethod
    def client_subject(cls) -> str | None:
        """Find client certificate subject."""
        peercert = request.environ.get("peercert")
        if peercert is None:
            return None
        components = peercert.get_subject().get_components()
        return "/".join(
            [f"{key.decode()}={value.decode()}" for key, value in components]
        )

    @classmethod
    def client_digest(cls) -> str | None:
        """Find client certificate digest."""
        peercert = request.environ.get("peercert")
        if peercert is None:
            return None
        digest = str(peercert.digest("sha256").decode().replace(":", "").lower())
        return digest
