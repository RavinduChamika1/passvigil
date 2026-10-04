"""
selftest.py - Prove the LIVE API integration works on YOUR machine.

Run:  python src/selftest.py

Three checks against the real api.pwnedpasswords.com:
  1. Connection works.
  2. A famous leaked password ('password') IS found with a big count.
  3. A random 40-character string is NOT found.
Each prints PASS or FAIL, so you know the integration is correct
before you record your demo.
"""
import secrets
import sys

import breach


def main() -> int:
    failures = 0

    # 1. Connectivity
    status = breach.check_connection()
    print(f"[{'PASS' if status.ok else 'FAIL'}] Connection: {status.message}"
          + (f" ({status.latency_ms:.0f} ms)" if status.latency_ms else ""))
    if not status.ok:
        print("Cannot reach the API. Check internet/firewall/VPN and try again.")
        return 1

    # 2. Known leaked password must be found (millions of times)
    r = breach.check_password("password")
    ok = r.pwned_count > 1_000_000
    failures += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] 'password' found {r.pwned_count:,} times "
          f"(prefix sent: {r.prefix_sent})")

    # 3. Random string must NOT be found
    random_pw = secrets.token_urlsafe(30)
    r = breach.check_password(random_pw)
    ok = r.pwned_count == 0
    failures += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] random string not found (count={r.pwned_count})")

    print("\nALL CHECKS PASSED: live integration works." if not failures
          else f"\n{failures} check(s) failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
