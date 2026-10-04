# What you learn in Week 1

1. **Hashing** - a one-way function. Same input, same output; you cannot reverse it.
2. **k-anonymity** - hide a record among many similar ones by revealing only a prefix.
3. **Entropy** - length x log2(character pool). A theoretical upper bound on strength.
4. **Pattern-based strength** - why `P@ssw0rd!` is weak: attackers guess human patterns (zxcvbn models this).
5. **Fast vs slow hashes** - the same password is cracked in seconds with SHA-1 but takes far longer with bcrypt/Argon2.

## Further reading
- Have I Been Pwned: Pwned Passwords API documentation (haveibeenpwned.com/API/v3)
- NIST SP 800-63B: Digital Identity Guidelines (password section)
- OWASP Authentication Cheat Sheet
- Dropbox engineering post on zxcvbn
