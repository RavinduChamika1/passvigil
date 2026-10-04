<p align="center">
  <img src="assets/logo.png" alt="PassVigil - Password Strength & Breach Checker" width="720">
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="API key" src="https://img.shields.io/badge/API%20key-not%20required-22D3EE">
  <img alt="Privacy" src="https://img.shields.io/badge/Password-never%20leaves%20your%20PC-success">
  <img alt="Series" src="https://img.shields.io/badge/52%20Weeks%20of%20Security-Week%201-blueviolet">
</p>

<p align="center">
  <b>Check how strong a password is and whether it has been leaked, without ever sending the password anywhere.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-why-this-tool-exists">Why this exists</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-usage">Usage</a> ·
  <a href="#-learn-from-this-project">Learn</a>
</p>

---

## 📌 Table of contents
- [Why this tool exists](#-why-this-tool-exists)
- [Why it is safer than online checkers](#-why-it-is-safer-than-online-checkers)
- [Features](#-features)
- [How it works](#-how-it-works)
- [Quick start](#-quick-start)
- [Usage](#-usage)
- [Example output](#-example-output)
- [Project structure](#-project-structure)
- [Testing](#-testing)
- [Security notes and limitations](#-security-notes-and-limitations)
- [Learn from this project](#-learn-from-this-project)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Why this tool exists

Billions of real passwords have been exposed in data breaches. Attackers collect them into wordlists and try them first on every account they target. So a password can look "complex" and still be unsafe if it has already leaked.

Most people cannot answer two simple questions:

1. **Is my password actually strong?** (not just "has a symbol")
2. **Has it already been leaked?**

This tool answers both in one command, on your own computer, in a few seconds.

---

## 🛡️ Why it is safer than online checkers

Typing a real password into a random website is a risk in itself. When you use a web-based checker, you are trusting a stranger's server and page with your secret.

| Risk with a website | What can go wrong | **PassVigil (this tool)** |
|---|---|---|
| **Server logging** | The site can record what you submit in server logs or a database | Nothing is submitted. Only a 5-character hash prefix is sent |
| **Cookies and browser storage** | Pages can save input in cookies, `localStorage`, or form autofill | No browser, no cookies, nothing saved. Hidden terminal input |
| **Analytics and third-party scripts** | Ad, tracking, or analytics scripts running on the page may see what you type | No third-party code. Only `requests`, `rich`, `zxcvbn` |
| **URL leaks** | Passwords sent in a URL end up in browser history, proxy logs, and referrer headers | Nothing is placed in a URL except the 5-character prefix |
| **Fake or lookalike sites** | An attacker can host a "password checker" whose only purpose is to collect passwords | You can read all of the source code before running it |
| **Browser extensions** | Extensions can read what you type into web pages | Runs in your terminal, outside the browser |
| **You cannot verify the code** | You never see what the site's backend does | Fully open source and covered by tests |

**How it protects you:** your password is hashed locally, and only the first 5 characters of that hash are sent. Hundreds of other leaked passwords share that same prefix, so the server cannot tell which one you checked. The final match happens on your computer.

> **Honest note:** the official Have I Been Pwned website uses the same k-anonymity method and is trustworthy. The point of this tool is that **you can audit every line**, nothing is stored, and it adds a **full strength analysis and learning material** that a simple lookup does not. It is also a good reminder never to paste real passwords into websites you cannot verify.

---

## ✨ Features

- ✅ **Connection check** before anything else, with a clear offline fallback
- 🔐 **Hidden password input** (`getpass`). Nothing is echoed, stored, or logged
- 📊 **Strength analysis** with [zxcvbn](https://github.com/dwolfhub/zxcvbn-python): score, entropy, crack-time estimates, and improvement tips
- 🔎 **Breach lookup** using the real [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3) (free, **no API key needed**)
- ⏳ **Live progress bar** showing each stage
- 🎨 **Clear, colour-coded report** with a final verdict
- 🔌 **`--offline` mode** (strength only, no internet)
- 🧪 **Offline unit tests** (the network is mocked)
- 🧰 **`selftest.py`** to prove the live API works on your machine

---

## 🔬 How it works

```
 You type a password (hidden)
          │
          ▼
 [1] Strength analysis ─────────────► score, entropy, crack time, tips   (local)
          │
          ▼
 [2] SHA-1 hash                      5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
          │                          └─┬─┘└─────────────┬─────────────────┘
          │                         prefix           suffix
          ▼                       (sent to API)   (never leaves your PC)
 [3] GET https://api.pwnedpasswords.com/range/5BAA6
          │
          ▼
 [4] API returns ~500-1000 leaked suffixes with counts
          │
          ▼
 [5] Your computer looks for its own suffix in that list
          │
          ▼
     "Found 52,372,427 times"  or  "Not found"
```

**This is called k-anonymity.** The server only ever sees the 5-character prefix, so your password stays private.

> SHA-1 is used here only because the API requires it. **SHA-1 is not safe for storing passwords.** (See Week 2 of the series.)

---

## 🚀 Quick start

You need **Python 3.10 or newer**. Check with `python --version`.

**1. Download the project**
```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/week-01-password-checker.git
cd week-01-password-checker
```

**2. Create and activate a virtual environment**
```bash
python -m venv .venv

# Windows (Command Prompt)
.venv\Scripts\activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Mac / Linux
source .venv/bin/activate
```

**3. Install the libraries**
```bash
pip install -r requirements.txt
```

**4. (Optional) Confirm the live API works**
```bash
python src/selftest.py
```
Expect `ALL CHECKS PASSED`.

**5. Run it**
```bash
python src/cli.py
```

---

## 💻 Usage

```bash
python src/cli.py              # full check: strength + breach lookup
python src/cli.py --offline    # strength only, no internet needed
python src/cli.py --fast       # skip the small demo delays in the progress bar
python src/cli.py --help       # show all options
```

**What happens when you run it**

1. The tool tests the connection to the API
2. You type your password (nothing appears on screen, this is normal)
3. A progress bar shows the analysis stages
4. A report appears with the strength, breach result, tips, and a verdict
5. You can check another password or quit

**Good passwords to try**

| Try this | Expected result |
|---|---|
| `password` | Leaked millions of times, **DO NOT USE** |
| `Tr0ub4dor&3` | Weak or fair |
| `purple-giraffe-drinks-tea-at-9!` | Strong and not found |

> ⚠️ Do not test your real, current passwords while screen-recording a demo.

---

## 📺 Example output

```text
─────────────── Step 3 of 4: Analysing ───────────────
  Analysis complete ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

─────────────── Step 4 of 4: Results ─────────────────
                    Strength Analysis
╭─────────────────────────────────────────────┬───────────────────────────╮
│  Rating                                     │  Very Weak  █░░░░  (0/4)  │
│  Length                                     │  8 characters             │
│  Entropy (theoretical)                      │  37.6 bits                │
│  Crack time (slow hash, e.g. bcrypt)        │  less than a second       │
│  Crack time (fast hash, e.g. leaked SHA-1)  │  less than a second       │
╰─────────────────────────────────────────────┴───────────────────────────╯

Breach Check
✘ FOUND in data breaches 52,372,427 times
  Privacy: only the prefix '5BAA6' was sent and compared locally.

╭─────────────────────────── Verdict ───────────────────────────╮
│ DO NOT USE: this password has been leaked.                    │
╰───────────────────────────────────────────────────────────────╯
```

*(Add your own screenshot or demo GIF here, for example `assets/demo.gif`.)*

---

## 🗂️ Project structure

```
week-01-password-checker/
├── src/
│   ├── cli.py            # program flow, progress bar, report
│   ├── breach.py         # SHA-1 hashing + HIBP k-anonymity lookup
│   ├── strength.py       # zxcvbn strength + entropy
│   ├── selftest.py       # live API verification
│   └── about.py          # author and copyright details
├── tests/
│   └── test_breach.py    # offline tests (mocked network)
├── labs/
│   ├── LAB.md            # student exercises
│   └── solutions/
├── LEARN.md              # key concepts and further reading
├── requirements.txt
├── pytest.ini
├── LICENSE
└── README.md
```

---

## 🧪 Testing

```bash
pytest
```

The tests mock the network, so they run offline. They verify that:
- the SHA-1 hash is split correctly
- **only the 5-character prefix** is ever sent (never the password or the rest of the hash)
- matching and padding entries work
- network errors are handled
- weak passwords score lower than strong ones

---

## 🔒 Security notes and limitations

- The password and full hash are **never** sent, printed, saved, or logged.
- "Not found" does **not** mean "safe". It only means the password is not in this dataset.
- The API still sees your IP address and the 5-character prefix, which on its own cannot identify your password.
- **If your computer is infected (for example with a keylogger), no tool can protect what you type.**
- Entropy is a theoretical upper bound. Real strength is often lower because people choose predictable patterns, which is why zxcvbn is used as well.
- Best practice: use a password manager, make passwords long and unique, and turn on multi-factor authentication.

**Disclaimer:** this project is for education and personal use. Only check passwords that belong to you. It is not affiliated with or endorsed by Have I Been Pwned or Troy Hunt.

---

## 📚 Learn from this project

Open [LEARN.md](LEARN.md) for the key concepts (hashing, k-anonymity, entropy, pattern-based strength, fast vs slow hashes) and further reading. Try the exercises in [labs/LAB.md](labs/LAB.md).

---

## 🗺️ Roadmap

Part of **52 Weeks of Security**: one new cybersecurity project every week.

- [x] **Week 1:** Password strength and breach checker
- [ ] **Week 2:** Hashing lab (MD5, SHA, bcrypt, Argon2)
- [ ] **Week 3:** Phishing URL analyzer
- [ ] More coming every week

Ideas for this project: batch-check a file of passwords, passphrase generator, JSON report export, Streamlit web interface.

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-idea`
3. Make your changes and run `pytest`
4. Commit and push, then open a Pull Request

Found a bug or have an idea? [Open an issue](https://github.com/YOUR-GITHUB-USERNAME/week-01-password-checker/issues).

---

## 👤 Author

**Ravindu Chamika**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/YOUR-LINKEDIN-USERNAME)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?logo=github&logoColor=white)](https://github.com/YOUR-GITHUB-USERNAME)

If this helped you learn something, please ⭐ the repo and follow the series.

---

## 📄 License

Copyright © 2026 **Ravindu Chamika**. Released under the [MIT License](LICENSE).

<p align="center"><sub>Built for cybersecurity students · 52 Weeks of Security · Week 1</sub></p>
