# basic_auth_credential_decoder

Decode and validate HTTP `Authorization: Basic` header credentials per RFC 7617.

```python
from basic_auth_credential_decoder import decode, parse_authorization_header

cred = decode("Basic YWxpY2U6czNjcmV0")
assert cred.username == "alice"
assert cred.password == "s3cret"

# If you only want the base64 token out of the header:
token = parse_authorization_header("Basic YWxpY2U6czNjcmV0")
```

## Why this exists

A surprising amount of code does `base64.b64decode(header.split(" ")[1]).split(b":")`
and calls it done. That breaks on passwords containing colons, on unpadded
base64, on headers with trailing newlines, and on anything that is not ASCII.
This library does the small amount of work required to get those cases right,
and raises a single `DecodeError` when the header is not usable so callers do
not have to distinguish a dozen failure modes.

The trade-off: this decoder assumes UTF-8. RFC 7617 lets a server advertise a
charset in the challenge, but the `Authorization` request header itself carries
no charset parameter, so a decoder that only sees the header cannot know. We
pick UTF-8 and reject bytes that are not valid UTF-8 instead of silently
replacing them, because a credential that round-trips through U+FFFD is worse
than one that fails loudly.

## API

- `decode(header: str) -> BasicAuthCredential` — full header to credential.
- `parse_authorization_header(header: str) -> str` — extract the base64 token,
  checking the scheme is `Basic` (case-insensitively).
- `BasicAuthCredential` — frozen dataclass with `username` and `password`.
- `DecodeError` — subclass of `ValueError` raised for every malformed input.

## The awkward edge

The username must not contain a colon; the password may. We split on the
*first* colon, which is what RFC 7617 specifies. If you feed in a credential
whose username contains a colon, you will get a username truncated at that
colon and the rest will end up in the password. There is no way to detect this
from the wire format alone.
