import unittest

from gitleaks_lite_cli.core import is_high_entropy, mask, scan_line, scan_text, shannon_entropy


class TestShannonEntropy(unittest.TestCase):
    def test_repeated_char_has_zero_entropy(self) -> None:
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_looking_string_has_higher_entropy(self) -> None:
        self.assertGreater(shannon_entropy("aA1bB2cC3dD4eE5f"), shannon_entropy("aaaaaaaaaaaaaaaa"))

    def test_empty_string_is_zero(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)


class TestIsHighEntropy(unittest.TestCase):
    def test_low_entropy_sequence_rejected(self) -> None:
        self.assertFalse(is_high_entropy("11111111111111111111111111111111"))

    def test_random_hex_accepted(self) -> None:
        self.assertTrue(is_high_entropy("9f1c6a3e7b2d4f8091c5a6b7d8e9f0a1"))


class TestMask(unittest.TestCase):
    def test_short_value_fully_masked(self) -> None:
        self.assertEqual(mask("abc"), "***")

    def test_long_value_keeps_first_and_last_four(self) -> None:
        result = mask("AKIAABCDEFGHIJKLMNOP")
        self.assertTrue(result.startswith("AKIA"))
        self.assertTrue(result.endswith("MNOP"))
        self.assertNotIn("BCDEFGHIJKL", result)

    def test_never_exposes_full_secret(self) -> None:
        secret = "supersecretvalue1234567890"
        self.assertNotEqual(mask(secret), secret)


class TestScanLine(unittest.TestCase):
    def test_detects_aws_access_key(self) -> None:
        findings = scan_line('aws_key = "AKIAABCDEFGHIJKLMNOP"', 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "AWS Access Key")
        self.assertEqual(findings[0].matched_value, "AKIAABCDEFGHIJKLMNOP")

    def test_detects_private_key_header(self) -> None:
        findings = scan_line("-----BEGIN RSA PRIVATE KEY-----", 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "Private Key Header")

    def test_detects_plain_private_key_header(self) -> None:
        findings = scan_line("-----BEGIN PRIVATE KEY-----", 1)
        self.assertEqual(len(findings), 1)

    def test_detects_generic_api_key(self) -> None:
        findings = scan_line('API_KEY="sk_live_abcdefgh12345678"', 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "Generic API Key")

    def test_detects_high_entropy_secret_assignment(self) -> None:
        findings = scan_line('secret_token = "9f1c6a3e7b2d4f8091c5a6b7d8e9f0a112345678"', 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "High-Entropy Secret Assignment")

    def test_low_entropy_long_value_not_flagged(self) -> None:
        findings = scan_line('password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"', 1)
        self.assertEqual(findings, [])

    def test_clean_line_has_no_findings(self) -> None:
        findings = scan_line("x = compute_total(price, quantity)", 1)
        self.assertEqual(findings, [])

    def test_does_not_double_report_overlapping_matches(self) -> None:
        # "api_key" also matches the generic sensitive-var-name rule; it
        # should only be reported once, by the more specific rule.
        findings = scan_line('api_key = "abcd1234efgh5678ijkl9012mnop3456"', 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "Generic API Key")


class TestScanText(unittest.TestCase):
    def test_reports_correct_line_numbers(self) -> None:
        text = "\n".join(
            [
                "x = 1",
                'aws_key = "AKIAABCDEFGHIJKLMNOP"',
                "y = 2",
            ]
        )
        findings = scan_text(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 2)

    def test_multiple_findings_across_lines(self) -> None:
        text = 'aws_key = "AKIAABCDEFGHIJKLMNOP"\n-----BEGIN RSA PRIVATE KEY-----\n'
        findings = scan_text(text)
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
