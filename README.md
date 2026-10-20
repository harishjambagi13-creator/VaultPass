# 🔐 VaultPass — Local Password Manager

VaultPass is a local, single-user password manager built with **FastAPI, SQLite, Jinja2, and vanilla JavaScript**.

It provides a modern dashboard for managing website credentials, generating strong passwords, and protecting saved records using browser-based encryption.

> **Project status:** Local-development and learning project. It has not undergone an independent security audit and should not be considered production-ready.

## ✨ Features

- 🔐 **Encrypted credential storage** using AES-256-GCM.
- 🌐 **Browser-side encryption and decryption** using the Web Crypto API.
- 🔑 **Master-password authentication** with a password-based key derivation process.
- 🗄️ **Local SQLite database** for storing encrypted credential records.
- 🛡️ **Challenge-response unlock flow** for authentication.
- ⏱️ **Automatic session expiration** after 30 minutes, with a live countdown.
- 🔒 **Vault locking** that discards the browser's in-memory encryption key.
- 🎲 **Cryptographically secure password generator** with configurable length.
- 🔎 **Credential search, category filtering and sorting** through a web dashboard.
- ⭐ **Favorites and categories** stored inside the encrypted record payload.
- 🛡️ **Security center** that detects weak and reused passwords locally.
- ⚙️ **Settings** for generator defaults, reveal timeout and list density.
- 🛡️ **CSRF protection** for state-changing requests.
- 🖥️ **Local-first architecture** without a requirement for a hosted backend.
- 🎨 **Art-directed dashboard** built on a cinematic background render and a self-hosted type system.

## 🎨 Dashboard design

The dashboard (the Overview page) is a single FastAPI-served view built with a small, deliberately
restrained design system:

- **Cinematic backdrop** — `static/images/vaultpass-dashboard-bg.webp` (with a `.jpg` fallback) is a
  generated midnight-navy render with abstract glass architecture, machined vault rings and blue/cyan
  light. A layered scrim and a fine grain tile (`vaultpass-grain.png`) keep text legible on top of it.
- **Glass surfaces** — panels use translucent fills, hairline borders and backdrop blur so the artwork
  reads through the interface.
- **Self-hosted Inter** — `static/fonts/` contains the variable Inter woff2 files, so typography works
  offline and satisfies the strict `font-src 'self'` Content Security Policy.
- **Iconography** — every icon is hand-written inline SVG; no icon font, no emoji, no CDN.
- **Responsive** — the sidebar becomes a slide-in drawer under 900px, metric cards reflow, and the
  credential table scrolls horizontally inside its own container.
- **Accessible** — labelled controls, `aria-pressed` state on toggles, visible focus rings and
  `prefers-reduced-motion` support.

Measured results from the automated browser suite: zero console errors, zero CSP violations, no
horizontal overflow at 390px or 1600px, and the credential table remains reachable at every breakpoint.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend application logic |
| FastAPI | API endpoints and web application |
| Uvicorn | ASGI development server |
| Jinja2 | HTML templating |
| SQLite | Local database |
| HTML5 | Page structure |
| CSS3 | Styling and responsive layout |
| JavaScript | Frontend interactions |
| Inter (self-hosted) | UI typography |
| Web Crypto API | Browser-side cryptographic operations |
| AES-256-GCM | Authenticated encryption |
| PBKDF2-HMAC-SHA-256 | Master-password-based key derivation |
| HKDF | Cryptographic key separation |
| Windows DPAPI | Protection of the authentication verifier on Windows |



## 📂 Project Structure

```text
VaultPass/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── static/
│   ├── css/
│   │   └── style.css            # design system + dashboard layout
│   ├── fonts/
│   │   ├── inter-latin.woff2    # self-hosted Inter (variable 400–700)
│   │   └── inter-latin-ext.woff2
│   ├── images/
│   │   ├── vaultpass-dashboard-bg.webp   # cinematic dashboard backdrop
│   │   ├── vaultpass-dashboard-bg.jpg    # fallback for older engines
│   │   ├── vaultpass-grain.png           # fine film-grain tile
│   │   └── favicon.svg
│   └── js/
│       └── app.js               # crypto, rendering and interactions
└── templates/
    └── index.html               # auth screen + dashboard shell
```

The local SQLite database is created as `vaultpass.sqlite3` by default, unless `VAULTPASS_DB_PATH` specifies another location.

## ⚙️ Installation and Setup

### Prerequisites

- Windows 10 or Windows 11
- Python installed and available in your PATH
- Git
- A modern browser that supports the Web Crypto API

### 1. Clone the repository

```powershell
git clone https://github.com/harishjambagi13-creator/VaultPass.git
```

### 2. Enter the project directory

```powershell
cd VaultPass
```

### 3. Create a virtual environment

```powershell
python -m venv venv
```

### 4. Activate the virtual environment

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 6. Start the application

```powershell
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

If port `8000` is unavailable on your computer, use port `8080` instead:

```powershell
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8080
```

### 7. Open VaultPass

For port 8000:

- **Application:** http://127.0.0.1:8000/
- **API documentation:** http://127.0.0.1:8000/docs
- **Health check:** http://127.0.0.1:8000/health

If you used port 8080, replace `8000` with `8080` in the URLs.

On first use, the application asks you to create a master password of at least 12 characters. Keep it safe: the application cannot recover a forgotten master password.

Press `Ctrl + C` in the terminal to stop the development server.

## 🔐 Security Architecture

VaultPass is designed to keep credential encryption and decryption in the browser.

### Encryption and key derivation

- Credential records are stored as AES-GCM authenticated ciphertext.
- Each record uses a random nonce and an authenticated record identifier.
- The browser uses PBKDF2-HMAC-SHA-256 with 600,000 iterations to derive key material from the master password.
- HKDF separates the derived material into keys for different cryptographic purposes.
- The master password is not sent to the server or stored as plaintext.
- The server stores a random per-vault salt and an authentication verifier.
- On Windows, DPAPI protects the authentication verifier for the current Windows user.

### Authentication and sessions

- Vault unlock uses a short-lived, single-use challenge-response proof.
- The protected verifier is not sent to the browser during login.
- Sessions are held in server memory and expire after 30 minutes.
- A random, HttpOnly, SameSite=Strict cookie identifies the session.
- State-changing requests require a CSRF token.
- The browser's derived encryption key remains in memory and is discarded when the vault is locked or the page is reloaded.

### Important limitations

VaultPass is a local-development project, not a production-ready hosted password manager.

- It supports a single user.
- There is no master-password recovery.
- There is no encrypted backup or export feature.
- Sessions are not persisted across server restarts.
- There has been no independent security audit.
- Anyone who compromises the computer, browser, or an unlocked session may be able to access vault data.
- Database recovery under a different Windows user account is not supported by the DPAPI-based verifier protection.
- Local development uses HTTP, so it should not be exposed to untrusted networks.
- The server cannot inspect credential fields because it intentionally receives encrypted records.

**A working authentication flow does not guarantee that the complete system is secure. Review and test the cryptographic implementation before storing real credentials.**

### Where favourites and categories live

Favourite flags and category labels are written **inside the encrypted credential payload**, not into a
separate column. The server still only ever stores opaque AES-GCM ciphertext, so the feature adds no
plaintext metadata to the database and no extra schema. Records written by earlier versions decrypt
normally and simply default to "not a favourite" and "no category".

### What the dashboard never stores

- Decrypted credentials, passwords, or vault keys are never written to `localStorage`.
- Revealed passwords live in a JavaScript `Map` for the lifetime of the tab and are never placed in the
  DOM, a `data-` attribute, or a URL.
- The only persisted browser state is a small, non-sensitive preferences object
  (`vaultpass.preferences.v1`) holding the generator length, reveal timeout and list density.
## Screenshots

### VaultPass Front Page
![VaultPass Front Page](screenshots/vaultpass-frontpage.png)

### VaultPass Dashboard
![VaultPass Dashboard](screenshots/vaultpass%20-dashboard.png)

### Password Vault
![Password Vault](screenshots/passwordvault.png)

## 🚧 Future Improvements

- Automated unit and integration tests
- Independent security review
- Encrypted backup and recovery design
- Improved accessibility and responsive behavior
- Password-strength analysis
- Password reuse warnings
- More comprehensive security documentation

## 👨‍💻 Author

**Harish Jambagi**

GitHub: [@harishjambagi13-creator](https://github.com/harishjambagi13-creator)

Project repository: [VaultPass](https://github.com/harishjambagi13-creator/VaultPass)

## 📄 License

No license has been specified yet. If you want others to reuse, modify, and distribute your project, consider adding an appropriate open-source license.
