# -*- coding: utf-8 -*-
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import icloud
from email_providers.common import extract_verification_code


class ICloudProviderTests(unittest.TestCase):
    def test_extract_xai_code(self):
        self.assertEqual(
            extract_verification_code("body", subject="ABC-DEF xAI"),
            "ABC-DEF",
        )

    def test_used_email_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "used.json")
            icloud.record_registered("A@iCloud.com", path, use_local_used=True, cloud_mark=False)
            icloud.record_registered("a@icloud.com", path, use_local_used=True, cloud_mark=False)
            used = icloud.load_used_emails(path)
            self.assertEqual(used, {"a@icloud.com"})
            self.assertTrue(icloud.is_registered("A@icloud.com", path))

    def test_record_registered_skips_local_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "used.json")
            icloud.record_registered("a@icloud.com", path, cloud_mark=False)
            self.assertEqual(icloud.load_used_emails(path), set())

    def test_collect_emails_from_accounts_files(self):
        with tempfile.TemporaryDirectory() as td:
            fp = Path(td) / "accounts_test.txt"
            fp.write_text(
                "one@icloud.com----pw----sso\n"
                "two@example.com----pw----sso\n",
                encoding="utf-8",
            )
            found = icloud.collect_emails_from_accounts_files(root=td)
            self.assertIn("one@icloud.com", found)
            self.assertIn("two@example.com", found)

    def test_acquire_email_wrapper_uses_lease(self):
        fake_lease = MagicMock()
        fake_lease.email = "x@icloud.com"
        fake_lease.anonymous_id = "aid"
        fake_lease.source = "inventory"
        with patch.object(icloud, "acquire_lease", return_value=fake_lease) as acq:
            email, anon, source = icloud.acquire_email_for_register("cookies=1")
        self.assertEqual((email, anon, source), ("x@icloud.com", "aid", "inventory"))
        acq.assert_called_once()

    def test_empty_cookies_raise(self):
        with self.assertRaises(Exception):
            icloud.create_alias_address("")


if __name__ == "__main__":
    unittest.main()
