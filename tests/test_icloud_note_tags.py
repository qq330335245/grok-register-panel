# -*- coding: utf-8 -*-
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers.icloud_note_tags import (
    format_note_tags,
    note_add_platform,
    note_has_platform,
    parse_note_tags,
)


class NoteTagTests(unittest.TestCase):
    def test_parse_and_add(self):
        self.assertEqual(parse_note_tags("openai, grok"), ["openai", "grok"])
        self.assertEqual(note_add_platform("openai", "grok"), "openai,grok")
        self.assertEqual(note_add_platform("openai,grok", "grok"), "openai,grok")
        self.assertTrue(note_has_platform("openai,grok", "grok"))
        self.assertFalse(note_has_platform("openai", "grok"))
        self.assertEqual(format_note_tags(["Google", "openai", "openai"]), "google,openai")


if __name__ == "__main__":
    unittest.main()
