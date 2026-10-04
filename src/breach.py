"""
breach.py - Check whether a password appears in known data breaches.

HOW IT WORKS (k-anonymity)
--------------------------
1. Hash the password with SHA-1 locally.        ->  5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
2. Send ONLY the first 5 characters (prefix).   ->  5BAA6
3. The API returns every leaked hash that starts with that prefix
   (usually 500-1000 entries) as "SUFFIX:COUNT" lines.
4. We look for our own suffix in that list, locally.

The full password and the full hash NEVER leave this computer.

NOTE: SHA-1 is used here only because the HIBP API requires it.
      SHA-1 is NOT safe for storing passwords (see Week 2).
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Optional

import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
# ------------------------------------------------------------------
# API KEY: NOT REQUIRED.
# The Pwned Passwords range endpoint is free and needs no authorisation
# (confirmed in the official HIBP docs: haveibeenpwned.com/API/v3).
# An API key (header "hibp-api-key") is only needed for the separate
# *breached account / email* endpoints, which are a paid feature.
# This tool does not use those endpoints.
# ------------------------------------------------------------------
API_URL = "https://api.pwnedpasswords.com/range/"   # real, live endpoint
TIMEOUT_SECONDS = 10                                # never wait forever
HEADERS = {
    # Good API etiquette: identify your tool.
    "User-Agent": "52-weeks-of-security-week01-password-checker",
    # Pads the response so a network observer cannot guess the result
    # from the response size.
    "Add-Padding": "true",
}


# --------------------------------------------------------------------------
# Data containers (make the results easy to read and test)
# --------------------------------------------------------------------------
class BreachCheckError(Exception):
    """Raised when the breach lookup cannot be completed."""


@dataclass
class ConnectionStatus:
    """Result of the pre-flight connectivity test."""
    ok: bool
    latency_ms: Optional[float]   # round-trip time, None if failed
    message: str                  # human-readable explanation


@dataclass
class BreachResult:
    """Result of a password breach lookup."""
    pwned_count: int      # times seen in breaches (0 = not found)
    prefix_sent: str      # the ONLY thing that was sent to the API
    candidates: int       # how many hashes the API returned for that prefix

    @property
    def is_pwned(self) -> bool:
        return self.pwned_count > 0


# --------------------------------------------------------------------------
# Step 0: connection test
# --------------------------------------------------------------------------
def check_connection() -> ConnectionStatus:
    """
    Make one harmless request (a fixed dummy prefix, not a real password)
    to verify the API is reachable before the user types anything.
    """
    start = time.perf_counter()
    try:
        response = requests.get(
            API_URL + "00000", headers=HEADERS, timeout=TIMEOUT_SECONDS
        )
        latency = (time.perf_counter() - start) * 1000

        if response.status_code == 200:
            return ConnectionStatus(True, latency, "API reachable")
        if response.status_code == 429:
            return ConnectionStatus(False, latency, "Rate limited by API (HTTP 429). Wait and retry.")
        return ConnectionStatus(False, latency, f"API returned HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return ConnectionStatus(False, None, "Connection timed out")
    except requests.exceptions.ConnectionError:
        return ConnectionStatus(False, None, "No internet connection or DNS failure")
    except requests.exceptions.RequestException as exc:
        return ConnectionStatus(False, None, f"Unexpected network error: {exc}")


# --------------------------------------------------------------------------
# Building blocks (small functions, easy to test)
# --------------------------------------------------------------------------
def hash_password(password: str) -> tuple[str, str]:
    """Return (prefix, suffix): first 5 and remaining 35 chars of the SHA-1 hash."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def fetch_range(prefix: str) -> str:
    """Ask the API for all hash suffixes that share this 5-character prefix."""
    try:
        response = requests.get(
            API_URL + prefix, headers=HEADERS, timeout=TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.Timeout as exc:
        raise BreachCheckError("The request timed out.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise BreachCheckError("Could not connect to the API.") from exc
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        raise BreachCheckError(f"API error (HTTP {code}).") from exc


def find_suffix(response_text: str, suffix: str) -> tuple[int, int]:
    """
    Search the API response for our suffix.
    Returns (count, total_lines). Padding entries have count 0, so they
    naturally never register as a breach.
    """
    lines = response_text.splitlines()
    for line in lines:
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            return int(count.strip()), len(lines)
    return 0, len(lines)


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def check_password(
    password: str,
    on_step: Optional[Callable[[str], None]] = None,
) -> BreachResult:
    """
    Run the full breach check.
    `on_step` is an optional callback used by the CLI to update the progress bar.
    """
    def notify(message: str) -> None:
        if on_step:
            on_step(message)

    notify("Hashing password locally (SHA-1)")
    prefix, suffix = hash_password(password)

    notify(f"Sending only prefix '{prefix}' to API")
    response_text = fetch_range(prefix)

    notify("Comparing results locally")
    count, total = find_suffix(response_text, suffix)

    return BreachResult(pwned_count=count, prefix_sent=prefix, candidates=total)
