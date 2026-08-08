"""Tests for engine/pii.py — email/phone/SSN/credit-card/API-key detectors,
including the Luhn-checksum false-positive guard for credit cards."""

from engine.pii import (
    find_api_keys,
    find_credit_cards,
    find_emails,
    find_phones,
    find_ssns,
    luhn_valid,
    scan_pii,
)

# Well-known card-network test numbers, all Luhn-valid.
VALID_TEST_CARDS = [
    "4111111111111111",  # Visa
    "5500005555555559",  # Mastercard
    "378282246310005",  # Amex (15 digits)
]


def test_luhn_valid_known_cards():
    for number in VALID_TEST_CARDS:
        assert luhn_valid(number), f"{number} should be Luhn-valid"


def test_luhn_rejects_sequential_digits():
    assert not luhn_valid("1234567890123456")


def test_find_emails():
    matches = find_emails("Contact me at jane.doe+work@example.co.uk for details.")
    assert len(matches) == 1
    assert matches[0].kind == "email"
    assert matches[0].category == "pii_leak"
    assert matches[0].matched_text == "jane.doe+work@example.co.uk"


def test_find_phones():
    matches = find_phones("Call me at (555) 123-4567 tomorrow.")
    assert len(matches) == 1
    assert matches[0].kind == "phone"


def test_find_ssns():
    matches = find_ssns("My SSN is 123-45-6789, please keep it safe.")
    assert len(matches) == 1
    assert matches[0].kind == "ssn"
    assert matches[0].severity == "high"


def test_find_ssns_rejects_invalid_area_number():
    # SSA never issues area number 000 or 666
    matches = find_ssns("Reference code 000-45-6789 was used on the form.")
    assert matches == []


def test_find_credit_cards_valid_luhn():
    matches = find_credit_cards(f"My card number is {VALID_TEST_CARDS[0]}.")
    assert len(matches) == 1
    assert matches[0].kind == "credit_card"


def test_find_credit_cards_rejects_non_luhn_digit_run():
    # A 16-digit run that fails the Luhn checksum should NOT be flagged —
    # this is the whole point of Luhn validation over a bare digit-count regex.
    matches = find_credit_cards("Order tracking number: 1234567890123456")
    assert matches == []


def test_find_credit_cards_rejects_phone_like_digit_runs():
    # Long invoice/account numbers shouldn't false-positive as cards either.
    matches = find_credit_cards("Invoice #: 9999888877776666")
    assert matches == []


def test_find_api_keys_openai():
    matches = find_api_keys("here is my key sk-abcdefghijklmnopqrstuvwxyz123456")
    assert any(m.kind == "api_key:openai_api_key" for m in matches)
    assert all(m.category == "exfiltration" for m in matches)


def test_find_api_keys_anthropic_not_misdetected_as_openai():
    matches = find_api_keys("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx")
    kinds = [m.kind for m in matches]
    assert "api_key:anthropic_api_key" in kinds
    assert "api_key:openai_api_key" not in kinds


def test_find_api_keys_github_and_aws():
    text = "token=ghp_" + "a" * 36 + " and AKIAABCDEFGHIJKLMNOP"
    matches = find_api_keys(text)
    kinds = {m.kind for m in matches}
    assert "api_key:github_token" in kinds
    assert "api_key:aws_access_key" in kinds


def test_scan_pii_combines_all_detectors():
    text = "Email jane@example.com or call 555-123-4567, card 4111111111111111."
    matches = scan_pii(text)
    kinds = {m.kind for m in matches}
    assert "email" in kinds
    assert "phone" in kinds
    assert "credit_card" in kinds


# ---------------------------------------------------------------------------
# False-positive edge cases
# ---------------------------------------------------------------------------

def test_benign_text_no_pii():
    text = "The quarterly report is due next Friday and covers Q3 revenue."
    assert scan_pii(text) == []


def test_order_number_not_flagged_as_card():
    # Random long numeric strings that happen to be 13-19 digits but fail
    # Luhn shouldn't be flagged as a credit card.
    matches = find_credit_cards("Tracking ID 1Z999AA10123456784 wasn't found.")
    assert matches == []
