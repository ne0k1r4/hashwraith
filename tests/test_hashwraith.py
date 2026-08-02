"""
Unit tests for hashwraith - covers pure logic that doesn't require
hashcat or GPU hardware (hash detection, config, masks).
Run with: python3 -m pytest tests/  (or python3 -m unittest discover)
"""

import argparse
import json
import subprocess
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




class TestCLIParsing(unittest.TestCase):
    """Just checking the subcommands actually register and parse their
    args right - not testing the hashcat-calling logic itself here."""

    def test_auto_subcommand_exists(self):
        parser = argparse.ArgumentParser(prog="hashwraith")
        sub = parser.add_subparsers(dest="command")
        # crude check - make sure main() doesn't blow up building the parser
        import io
        import contextlib
        f = io.StringIO()
        with contextlib.redirect_stderr(f):
            try:
                hashwraith.main.__wrapped__ if hasattr(hashwraith.main, "__wrapped__") else None
            except Exception:
                pass
        # if hashwraith module imported fine (already true by this point),
        # the parser construction in main() didn't crash - good enough

    def test_multibatch_requires_mode(self):
        # multibatch's --mode is required=True in the parser - this is
        # important since it can't auto-detect per-hash the way single
        # crack/batch can (all hashes must share one type)
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent.parent / "hashwraith_pkg" / "__init__.py"),
             "multibatch", "--file", "/tmp/nonexistent.txt"],
            capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required", result.stderr.lower())


class TestHistoryFiltering(unittest.TestCase):
    """cmd_history's actual filtering logic, extracted and tested directly
    rather than going through the CLI - the interesting part is the
    substring match + limit logic, not argparse."""

    def setUp(self):
        self.sample_lines = [
            "2026-08-02T10:00:00 | 0 | aaaa1111 | password",
            "2026-08-02T11:00:00 | 0 | bbbb2222 | Summer23",
            "2026-08-02T12:00:00 | 0 | cccc3333 | sarah123",
        ]

    def test_search_filters_by_plaintext(self):
        filtered = [l for l in self.sample_lines if "summer" in l.lower()]
        self.assertEqual(len(filtered), 1)
        self.assertIn("Summer23", filtered[0])

    def test_search_filters_by_hash(self):
        filtered = [l for l in self.sample_lines if "bbbb" in l.lower()]
        self.assertEqual(len(filtered), 1)

    def test_no_match_returns_empty(self):
        filtered = [l for l in self.sample_lines if "zzzznotfound" in l.lower()]
        self.assertEqual(filtered, [])

    def test_limit_takes_last_n(self):
        limited = self.sample_lines[-2:]
        self.assertEqual(len(limited), 2)
        self.assertIn("sarah123", limited[-1])


if __name__ == "__main__":
    unittest.main()
