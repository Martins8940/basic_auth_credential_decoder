"""Decode and validate HTTP Basic Authorization credentials per RFC 7617.

RFC 7617 defines the ``Basic`` authentication scheme. The credential is the
base64 encoding of ``user-id ":" password``. The user-id must not contain a
colon, and the whole credential is decoded as UTF-8 unless the server has
signalled a different charset. There is no way to negotiate a charset from
inside a single header value, so this module decodes strictly as UTF-8 and
reports failure rather than silently substituting replacement characters.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass


class DecodeError(ValueError):
    """Raised when an Authorization header cannot be decoded."""


@dataclass(frozen=True)
class BasicAuthCredential:
    """A decoded Basic Auth credential.

    ``username`` and ``password`` are exactly the strings that appeared
    before and after the first colon in the decoded octets. The password is
    allowed to contain colons; the username is not.
    """

    username: str
    password: str


def parse_authorization_header(header: str) -> str:
    """Return the base64 token from an ``Authorization: Basic <token>`` value.

    The scheme name is compared case-insensitively because RFC 7235 defines
    auth-scheme as case-insensitive. Exactly one space is required between the
    scheme and the token, matching the ABNF in RFC 7617; a header with no token
    is rejected rather than treated as an empty credential.
    """
    if not isinstance(header, str):
        raise DecodeError("header must be a string")
    parts = header.split(" ", 1)
    if len(parts) != 2:
        raise DecodeError("authorization header is missing a token")
    scheme, token = parts
    if scheme.lower() != "basic":
        raise DecodeError(f"unsupported authorization scheme: {scheme!r}")
    if not token:
        raise DecodeError("authorization header is missing a token")
    return token


def _decode_base64(token: str) -> bytes:
    """Decode the base64 token, rejecting malformed input.

    ``base64.b64decode`` with ``validate=True`` rejects characters outside the
    base64 alphabet, but it still accepts a missing padding character on some
    inputs. We normalize padding ourselves so the error is consistent.
    """
    if not isinstance(token, str):
        raise DecodeError("token must be a string")
    stripped = token.strip()
    if not stripped:
        raise DecodeError("empty credential token")
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base64 in credential: {exc}") from exc


def decode(header: str) -> BasicAuthCredential:
    """Decode a full ``Authorization`` header value into a credential.

    Raises :class:`DecodeError` if the scheme is not ``Basic``, the base64 is
    malformed, the decoded octets are not valid UTF-8, or the decoded value
    contains no colon separating username from password.
    """
    token = parse_authorization_header(header)
    raw = _decode_base64(token)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("credential is not valid UTF-8") from exc
    if ":" not in text:
        raise DecodeError("credential is missing the username/password separator")
    username, password = text.split(":", 1)
    return BasicAuthCredential(username=username, password=password)
