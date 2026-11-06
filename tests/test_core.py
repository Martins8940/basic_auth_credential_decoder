import base64
import unittest

from basic_auth_credential_decoder import (
    BasicAuthCredential,
    DecodeError,
    decode,
    parse_authorization_header,
)


def basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class ParseAuthorizationHeaderTests(unittest.TestCase):
    def test_extracts_token(self):
        self.assertEqual(parse_authorization_header("Basic dXNlcjpwYXNz"), "dXNlcjpwYXNz")

    def test_scheme_is_case_insensitive(self):
        self.assertEqual(parse_authorization_header("basic dXNlcjpwYXNz"), "dXNlcjpwYXNz")
        self.assertEqual(parse_authorization_header("BASIC dXNlcjpwYXNz"), "dXNlcjpwYXNz")

    def test_rejects_other_scheme(self):
        with self.assertRaises(DecodeError):
            parse_authorization_header("Bearer dXNlcjpwYXNz")

    def test_rejects_missing_token(self):
        with self.assertRaises(DecodeError):
            parse_authorization_header("Basic")
        with self.assertRaises(DecodeError):
            parse_authorization_header("Basic ")

    def test_rejects_non_string(self):
        with self.assertRaises(DecodeError):
            parse_authorization_header(None)  # type: ignore[arg-type]


class DecodeTests(unittest.TestCase):
    def test_happy_path(self):
        cred = decode(basic("alice", "s3cret"))
        self.assertEqual(cred, BasicAuthCredential(username="alice", password="s3cret"))

    def test_password_may_contain_colons(self):
        cred = decode(basic("alice", "a:b:c"))
        self.assertEqual(cred.username, "alice")
        self.assertEqual(cred.password, "a:b:c")

    def test_empty_password_is_allowed(self):
        cred = decode(basic("alice", ""))
        self.assertEqual(cred.username, "alice")
        self.assertEqual(cred.password, "")

    def test_empty_username_is_allowed(self):
        cred = decode(basic("", "pw"))
        self.assertEqual(cred.username, "")
        self.assertEqual(cred.password, "pw")

    def test_unicode_roundtrip(self):
        cred = decode(basic("\u00e5sa", "p\u00e4ssw\u00f6rd"))
        self.assertEqual(cred.username, "\u00e5sa")
        self.assertEqual(cred.password, "p\u00e4ssw\u00f6rd")

    def test_missing_separator(self):
        token = base64.b64encode(b"noseparator").decode("ascii")
        with self.assertRaises(DecodeError):
            decode("Basic " + token)

    def test_invalid_base64(self):
        with self.assertRaises(DecodeError):
            decode("Basic !!!!!!")

    def test_invalid_utf8(self):
        token = base64.b64encode(b"\xff\xfe:pw").decode("ascii")
        with self.assertRaises(DecodeError):
            decode("Basic " + token)

    def test_unpadded_base64_is_accepted(self):
        # "alice:pw" encodes to 10 bytes; strip the trailing padding to make
        # sure we normalize it rather than rejecting a valid token.
        token = base64.b64encode(b"alice:pw").decode("ascii").rstrip("=")
        cred = decode("Basic " + token)
        self.assertEqual(cred, BasicAuthCredential(username="alice", password="pw"))

    def test_token_with_surrounding_whitespace(self):
        token = base64.b64encode(b"alice:pw").decode("ascii")
        cred = decode("Basic " + token + "\n")
        self.assertEqual(cred, BasicAuthCredential(username="alice", password="pw"))

    def test_rejects_non_string_header(self):
        with self.assertRaises(DecodeError):
            decode(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
