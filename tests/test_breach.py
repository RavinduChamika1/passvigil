"""Tests run WITHOUT the network by mocking the API response."""
from unittest.mock import patch, Mock

import requests
import pytest

import breach
import strength

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PASSWORD = "password"
PREFIX, SUFFIX = "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def fake_response(text, status=200):
    m = Mock()
    m.status_code = status
    m.text = text
    m.raise_for_status = Mock()
    return m


def test_hash_password_splits_correctly():
    assert breach.hash_password(PASSWORD) == (PREFIX, SUFFIX)


def test_find_suffix_found():
    body = f"AAAAA:1\r\n{SUFFIX}:12345\r\nBBBBB:0"
    assert breach.find_suffix(body, SUFFIX) == (12345, 3)


def test_find_suffix_not_found_and_padding_ignored():
    body = "AAAAA:1\r\nPADDING:0"
    assert breach.find_suffix(body, SUFFIX)[0] == 0


def test_check_password_sends_only_prefix():
    secret = "Zq9-unique-test-value"          # distinct from any URL text
    prefix, suffix = breach.hash_password(secret)
    with patch("breach.requests.get", return_value=fake_response(f"{suffix}:99")) as get:
        result = breach.check_password(secret)
    called_url = get.call_args[0][0]
    assert called_url.endswith(prefix)          # only 5 chars sent
    assert suffix not in called_url             # never the rest of the hash
    assert secret not in called_url             # never the password
    assert result.is_pwned and result.pwned_count == 99


def test_network_error_becomes_breach_error():
    with patch("breach.requests.get", side_effect=requests.exceptions.ConnectionError):
        with pytest.raises(breach.BreachCheckError):
            breach.check_password(PASSWORD)


def test_connection_check_ok_and_failure():
    with patch("breach.requests.get", return_value=fake_response("", 200)):
        assert breach.check_connection().ok
    with patch("breach.requests.get", side_effect=requests.exceptions.Timeout):
        status = breach.check_connection()
        assert not status.ok and "timed out" in status.message.lower()


def test_strength_weak_vs_strong():
    weak = strength.analyze("password123")
    strong = strength.analyze("correct-horse-battery-staple-92!")
    assert weak.score < strong.score
    assert strong.entropy_bits > weak.entropy_bits
