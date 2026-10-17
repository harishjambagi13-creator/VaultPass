# VaultPass

VaultPass is a local, single-user password manager built with FastAPI, Jinja2,
plain JavaScript, and SQLite.

## Run on Windows

Install or update packages in the existing virtual environment, then start the
development server from the project directory:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app:app --reload
```

Open <http://127.0.0.1:8000/>. The first visit asks you to create a master
password with at least 12 characters. Keep it safe: VaultPass cannot recover a
forgotten master password. The API documentation is at
<http://127.0.0.1:8000/docs>, and the health check is at
<http://127.0.0.1:8000/health>.

## Data and security

- SQLite stores each complete credential record as AES-GCM authenticated
  ciphertext. Encryption and decryption happen in the browser with the Web
  Crypto API; credential API responses contain ciphertext, not passwords,
  usernames, or website names. The database file is `vaultpass.sqlite3` in
  this project folder by default; set `VAULTPASS_DB_PATH` to use a different
  location.
- A random per-vault salt and a PBKDF2-derived authentication verifier are
  stored in SQLite. The verifier is protected with Windows DPAPI for the
  current Windows user; legacy plaintext verifier records are wrapped during
  application startup without changing saved credential records. The master
  password is never sent to the server or stored. The browser uses
  PBKDF2-HMAC-SHA-256 (600,000 iterations), then HKDF to separate the verifier
  and AES-256 encryption keys. Each record has its own random nonce and
  authenticated record identifier. Unlock uses a short-lived, single-use
  challenge-response proof; the protected verifier is not sent on login.
- The derived encryption key stays in browser memory and is discarded on lock
  or page reload, so re-enter the master password after refreshing. The server
  keeps only short-lived in-memory sessions for 30 minutes. A random, HttpOnly,
  SameSite=Strict cookie identifies a session; state-changing requests also
  require a CSRF token.
- For local HTTP development, the session cookie's `Secure` flag is off. It is
  enabled automatically when `VAULTPASS_ENV=production` (or
  `ENVIRONMENT=production`); when serving behind HTTPS, you can also set
  `VAULTPASS_SECURE_COOKIES=1`.
- The password generator uses the browser's cryptographically secure random
  API and guarantees lowercase, uppercase, numeric, and symbol characters.

This is a local-development application, not a production-ready hosted password
manager. It has no multi-user support, master-password recovery, encrypted
backup/export, account recovery, persistent session store, or external
security audit. Anyone able to run code as the local user, compromise the
browser, or inspect an unlocked browser session can potentially access vault
data. Protect the device and database backups, keep the master password
private, and do not expose this development server to an untrusted network.
The DPAPI-protected verifier is bound to the Windows user profile that created
it; restoring the database under another Windows account is not supported.
Because the server intentionally cannot decrypt vault records, it can validate
ciphertext framing and size but cannot inspect encrypted credential fields;
the browser validates their field lengths before encryption.
