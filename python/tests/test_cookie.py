"""Decoder intentionally works on fake fixtures and never calls any remote service."""
import base64
import hashlib
import json
import unittest
from urllib.parse import quote

from pun_mcp.cookie_codec import inspect_value, inspect_cookie_header, verify_hash_candidate


class CookieCodecTests(unittest.TestCase):
    def test_nested_url_base64_json_and_redaction(self):
        original = '{"user_id":42,"role":"tester"}'
        encoded = quote(base64.b64encode(original.encode()).decode(), safe='')
        result = inspect_value(encoded)
        self.assertEqual(result["structure"], "json")
        self.assertEqual(result["json_keys"], ["role", "user_id"])
        self.assertIn("base64", result["encoding_chain"])
        self.assertNotIn("42", json.dumps(result))
        self.assertNotIn("decoded_local", result)
        local = inspect_value(encoded, include_values=True)
        self.assertEqual(local["decoded_local"], original)

    def test_jwt_without_exporting_secret_claim_values(self):
        h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
        p = base64.urlsafe_b64encode(b'{"sub":"alice@example.test","admin":false}').decode().rstrip('=')
        token = f'{h}.{p}.'
        result = inspect_value(token)
        self.assertEqual(result["structure"], "jwt")
        self.assertEqual(result["jwt"]["algorithm"], "none")
        self.assertEqual(result["jwt"]["claim_keys"], ["admin", "sub"])
        self.assertNotIn('alice@example.test', json.dumps(result))
        self.assertNotIn(token, json.dumps(result))

    def test_md5_sha_ones_are_only_recognized(self):
        digest = hashlib.md5(b'test').hexdigest()
        obj = inspect_value(digest)
        self.assertEqual(obj["structure"], "hash")
        self.assertIn("MD5", obj["hash_family"])
        self.assertEqual(obj["encoding_chain"], [])
        self.assertTrue(verify_hash_candidate(digest, 'test')["matches_candidate"])
        self.assertFalse(verify_hash_candidate(digest, 'nope')["matches_candidate"])
        sha = hashlib.sha256(b'test').hexdigest()
        self.assertIn('SHA-256', inspect_value(sha)['hash_family'])
        with self.assertRaises(ValueError):
            verify_hash_candidate('not-a-hash', 'abc')

    def test_header_splits_without_values_in_safe_mode(self):
        cookie = 'sid=YWJjZA==; setting=%7B%22theme%22%3A%22light%22%7D'
        rows = inspect_cookie_header(cookie)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['encoding_chain'], ["base64"])
        self.assertEqual(rows[1]['json_keys'], ["theme"])
        self.assertNotIn('abcd', json.dumps(rows))

    def test_invalid_and_oversized_bounded(self):
        self.assertIn('error', inspect_value('A' * 100000))
        self.assertEqual(inspect_value('%FF')['structure'], 'text')
        self.assertEqual(inspect_value('Ab-==')['encoding_chain'], [])
        self.assertEqual(len(inspect_cookie_header('bad; __Host-id=QUJDRA==')), 1)

    def test_hex_is_decodeable_if_not_a_hash(self):
        obj = inspect_value('68656c6c6f')
        self.assertEqual(obj['encoding_chain'], ['hex'])
        self.assertEqual(inspect_value('68656c6c6f', include_values=True)['decoded_local'], 'hello')


if __name__ == '__main__':
    unittest.main()
