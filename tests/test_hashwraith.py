"""
Unit tests for hashwraith - covers pure logic that doesn't require
hashcat or GPU hardware (hash detection, config, masks).
Run with: python3 -m pytest tests/  (or python3 -m unittest discover)
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import hashwraith_pkg as hashwraith


class TestHashDetection(unittest.TestCase):
    def test_md5(self):
        result = hashwraith.detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIn((0, "MD5"), result)

    def test_sha1(self):
        result = hashwraith.detect_hash_type("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        self.assertIn((100, "SHA1"), result)

    def test_sha256(self):
        result = hashwraith.detect_hash_type(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d1"[:64]
        )
        self.assertIn((1400, "SHA256"), result)

    def test_bcrypt(self):
        result = hashwraith.detect_hash_type(
            "$2b$12$KIXQ6h4/rB.9J3Yy8vJZLOWQXf5Xz5X5X5X5X5X5X5X5X5X5X5X5X"
        )
        self.assertIn((3200, "bcrypt"), result)

    def test_md5crypt(self):
        result = hashwraith.detect_hash_type("$1$abcdefgh$abcdefghijklmnopqrstu1")
        self.assertIn((500, "md5crypt / Cisco-IOS type 5"), result)

    def test_django_pbkdf2(self):
        result = hashwraith.detect_hash_type(
            "pbkdf2_sha256$260000$somesalt$somehashvaluehere"
        )
        self.assertIn((10000, "Django PBKDF2-SHA256"), result)

    def test_kerberos_tgs(self):
        result = hashwraith.detect_hash_type("$krb5tgs$23$*user$realm$spn*$deadbeef")
        self.assertIn((13100, "Kerberos 5 TGS-REP (Kerberoasting)"), result)

    def test_unrecognized_string_returns_empty(self):
        result = hashwraith.detect_hash_type("this is not a hash at all")
        self.assertEqual(result, [])

    def test_empty_string_returns_empty(self):
        result = hashwraith.detect_hash_type("")
        self.assertEqual(result, [])

    def test_whitespace_is_stripped(self):
        result = hashwraith.detect_hash_type("  5f4dcc3b5aa765d61d8327deb882cf99  \n")
        self.assertIn((0, "MD5"), result)


class TestConfig(unittest.TestCase):
    def setUp(self):
        # Redirect config to a temp location so tests never touch the real one
        self.tmpdir = Path("/tmp/hashwraith_test_config")
        self.tmpdir.mkdir(exist_ok=True)
        self.original_config_dir = hashwraith.CONFIG_DIR
        self.original_config_file = hashwraith.CONFIG_FILE
        hashwraith.CONFIG_DIR = self.tmpdir
        hashwraith.CONFIG_FILE = self.tmpdir / "config.json"

    def tearDown(self):
        if hashwraith.CONFIG_FILE.exists():
            hashwraith.CONFIG_FILE.unlink()
        hashwraith.CONFIG_DIR = self.original_config_dir
        hashwraith.CONFIG_FILE = self.original_config_file

    def test_load_config_returns_defaults_when_missing(self):
        cfg = hashwraith.load_config()
        self.assertEqual(cfg["default_wordlist"], None)

    def test_save_and_load_roundtrip(self):
        cfg = hashwraith.load_config()
        cfg["default_wordlist"] = "/some/path.txt"
        hashwraith.save_config(cfg)
        reloaded = hashwraith.load_config()
        self.assertEqual(reloaded["default_wordlist"], "/some/path.txt")

    def test_corrupted_config_falls_back_to_defaults(self):
        hashwraith.ensure_dirs()
        hashwraith.CONFIG_FILE.write_text("not valid json{{{")
        cfg = hashwraith.load_config()
        self.assertEqual(cfg["default_wordlist"], None)


class TestMasks(unittest.TestCase):
    def test_common_masks_are_valid_hashcat_syntax(self):
        valid_chars = set("lduas?")
        for name, pattern in hashwraith.COMMON_MASKS.items():
            cleaned = pattern.replace("?", "")
            self.assertTrue(
                all(c in "lduas" for c in cleaned),
                f"Mask '{pattern}' for '{name}' has invalid characters",
            )

    def test_all_masks_start_with_question_mark(self):
        for name, pattern in hashwraith.COMMON_MASKS.items():
            self.assertTrue(pattern.startswith("?"), f"Mask '{pattern}' should start with ?")


class TestPathChecking(unittest.TestCase):
    def test_none_path_is_valid(self):
        self.assertTrue(hashwraith.check_path_exists(None, "test"))

    def test_nonexistent_path_fails(self):
        self.assertFalse(hashwraith.check_path_exists("/nonexistent/path/xyz123.txt", "test"))

    def test_existing_file_passes(self):
        self.assertTrue(hashwraith.check_path_exists(__file__, "test"))

    def test_directory_is_not_a_valid_file(self):
        self.assertFalse(hashwraith.check_path_exists(str(Path(__file__).parent), "test"))


if __name__ == "__main__":
    unittest.main()
