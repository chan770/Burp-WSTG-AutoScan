# 🛡️ Burp WSTG Auto-Scan — OWASP WSTG Coverage for Burp Suite

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%2B%20Community-FF6633?style=flat-square&logo=burpsuite&logoColor=white)
![Montoya API](https://img.shields.io/badge/Montoya%20API-2026.4-000000?style=flat-square)
![OWASP WSTG](https://img.shields.io/badge/OWASP-WSTG%20v4.2-000000?style=flat-square&logo=owasp)
![Test Cases](https://img.shields.io/badge/WSTG%20Test%20Cases-113-22c55e?style=flat-square)
![Java](https://img.shields.io/badge/Java-17%2B-007396?style=flat-square&logo=openjdk&logoColor=white)
![CI](https://img.shields.io/github/actions/workflow/status/chan770/Burp-WSTG-AutoScan/ci.yml?style=flat-square&label=CI)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

A **Burp Suite extension** (Montoya API) that executes the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) **chapter-4** test cases and produces a professional, **WSTG-structured HTML report** — a full per-section coverage matrix plus detailed findings, each proven with the **real HTTP request and response**.

- On **Burp Professional** it drives Burp's **native Scanner** (active + passive audit) and merges those findings.
- On **Burp Community** (Scanner unavailable) it runs its own built-in active + passive checks.

---

## ✨ Features

- ✅ **113 WSTG test cases** catalogued across all 12 sections (4.1 → 4.12)
- ✅ **Coverage matrix** — every test case marked `PASS` / `FINDING` / `INFO` / `MANUAL` / `N-A`
- ✅ **Real request + response proof** on every finding, with the payload/evidence **highlighted**
- ✅ **Pro mode** — leverages Burp's native Scanner audit via `api.scanner().startAudit(...)`
- ✅ **Community mode** — self-contained checks: reflected XSS, SQLi, SSTI, CRLF, host-header injection, traversal/LFI, open redirect, CORS, clickjacking, security headers, cookie flags, sensitive-file & admin-interface enumeration, HTTP methods, API recon, and more
- ✅ **WSTG report format** — Introduction · Executive Summary · Coverage Matrix · Findings Details · References
- ✅ **CWE + WSTG IDs** mapped on every finding
- ✅ **Zero-config** — auto-runs on load; or set a target and click **Run WSTG Scan**

---

## 🧭 WSTG Coverage (chapter 4)

| Section | Examples of automated checks |
|---|---|
| **4.1 Information Gathering** | Server fingerprint, metafiles, framework fingerprint, content leakage, entry points |
| **4.2 Configuration & Deployment** | Security headers, CSP, HSTS, backup/sensitive files, admin interfaces, HTTP methods, RIA cross-domain, path confusion |
| **4.3 Identity Management** | Account-enumeration guidance *(manual)* |
| **4.4 Authentication** | Credentials over cleartext, browser-cache weaknesses |
| **4.5 Authorization** | Directory traversal / LFI |
| **4.6 Session Management** | Cookie attributes, CSRF token presence, JWT detection, exposed session vars |
| **4.7 Input Validation** | Reflected XSS, SQLi, HPP, SSTI, CRLF/response splitting, host-header injection, verb tampering |
| **4.8 Error Handling** | Verbose errors, stack-trace disclosure |
| **4.9 Weak Cryptography** | Sensitive data over unencrypted channel |
| **4.10 Business Logic** | Flagged for manual testing |
| **4.11 Client-side** | HTML injection, open redirect, CORS, clickjacking, reverse tabnabbing |
| **4.12 API Testing** | API/spec recon, GraphQL endpoint detection |

> Stateful, authenticated and business-logic test cases (stored XSS, IDOR, OAuth, MFA, payment, workflow, etc.) are **listed and flagged `MANUAL`** so coverage is complete and honest.

---

## 📸 Sample report

A rendered example is included at [`docs/sample-report.html`](docs/sample-report.html) — open it in a browser to see the coverage matrix and request/response proof.

---

## 🏗️ Project Structure

```
Burp-WSTG-AutoScan/
├── src/autoscan/
│   └── AutoScanExtension.java   # The extension (Montoya API)
├── dist/
│   └── autoscan.jar             # Prebuilt — load this in Burp
├── docs/
│   └── sample-report.html       # Example WSTG report
├── test/
│   └── VulnServer.java          # Deliberately-vulnerable demo target
├── build.gradle
└── .github/workflows/ci.yml
```

---

## ⚡ Getting Started

### Load the prebuilt extension
1. Burp Suite → **Extensions → Add**
2. **Extension type:** Java
3. **Select file:** `dist/autoscan.jar`
4. Open the **Auto Scan** tab, set a target origin, and click **Run WSTG Scan**.
   The report is written to `report.html` (path configurable in the source).

### Build from source
Requires JDK 17+ and the Montoya API (fetched from Maven Central).

```bash
# Gradle
gradle jar

# …or plain javac
curl -L -o montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.4/montoya-api-2026.4.jar
javac --release 17 -cp montoya-api.jar -d out src/autoscan/AutoScanExtension.java
jar --create --file dist/autoscan.jar -C out .
```

### Try it against the demo target
```bash
javac -d test test/VulnServer.java
java -cp test VulnServer 5599      # serves http://localhost:5599
# then point the extension at http://localhost:5599
```

---

## 🔬 How it works

| Mode | Engine |
|---|---|
| **Burp Professional** | `api.burpSuite().version().edition()` is detected; the extension starts a passive + active **native audit**, waits for it to settle, and maps each `AuditIssue` (with Burp's own request/response markers) into the WSTG report. |
| **Burp Community** | The Scanner API is Pro-only, so the extension performs its own HTTP-based active + passive checks using the Montoya `Http` API. |

Both paths populate the same **WSTG coverage matrix** and **findings details**, and every finding includes the captured HTTP request and response as proof.

---

## 📄 License

MIT — free to use, copy, and adapt.

---

> Built with the **Burp Montoya API** · Methodology by the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
