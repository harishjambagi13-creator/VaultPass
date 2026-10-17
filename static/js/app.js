"use strict";

const state = {
    csrfToken: "",
    salt: "",
    encryptionKey: null,
    credentials: [],
    editingId: null,
    activeView: "overview",
    generatedPassword: ""
};

const elements = {};

function byId(id) {
    return document.getElementById(id);
}

function encodeBase64(bytes) {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function decodeBase64(value) {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function deriveVaultKeys(masterPassword, salt) {
    const encoder = new TextEncoder();
    const passwordMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(masterPassword),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    const rootMaterial = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: 600000,
            hash: "SHA-256"
        },
        passwordMaterial,
        256
    );
    const hkdfMaterial = await crypto.subtle.importKey(
        "raw",
        rootMaterial,
        "HKDF",
        false,
        ["deriveBits", "deriveKey"]
    );
    const authVerifier = new Uint8Array(await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt,
            info: encoder.encode("VaultPass auth verifier v1")
        },
        hkdfMaterial,
        256
    ));
    const encryptionKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt,
            info: encoder.encode("VaultPass AES-GCM encryption key v1")
        },
        hkdfMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    return { authVerifier, encryptionKey };
}

async function createLoginProof(authVerifier, challenge, challengeId) {
    const key = await crypto.subtle.importKey(
        "raw",
        authVerifier,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const challengeBytes = decodeBase64(challenge);
    const idBytes = new TextEncoder().encode(challengeId);
    const message = new Uint8Array(challengeBytes.length + idBytes.length);
    message.set(challengeBytes);
    message.set(idBytes, challengeBytes.length);
    const signature = await crypto.subtle.sign("HMAC", key, message);
    return encodeBase64(new Uint8Array(signature));
}

function credentialAdditionalData(credentialId) {
    return new TextEncoder().encode(`vaultpass:credential:v1:${credentialId}`);
}

async function encryptCredentialPayload(credentialId, payload) {
    if (!state.encryptionKey) {
        throw new Error("Unlock the vault before saving credentials.");
    }
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: nonce,
            additionalData: credentialAdditionalData(credentialId)
        },
        state.encryptionKey,
        new TextEncoder().encode(JSON.stringify(payload))
    ));
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    return { id: credentialId, encrypted_data: encodeBase64(combined) };
}

async function decryptCredentialRecord(record) {
    if (!state.encryptionKey) {
        throw new Error("Unlock the vault to read saved credentials.");
    }
    const combined = decodeBase64(record.encrypted_data);
    if (combined.length < 28) {
        throw new Error("A saved vault record is incomplete or corrupted.");
    }
    let plaintext;
    try {
        plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: combined.slice(0, 12),
                additionalData: credentialAdditionalData(record.id)
            },
            state.encryptionKey,
            combined.slice(12)
        );
    } catch (error) {
        if (error instanceof DOMException && error.name === "OperationError") {
            throw new Error("A saved record could not be authenticated or decrypted.");
        }
        throw error;
    }
    let credential;
    try {
        credential = JSON.parse(new TextDecoder().decode(plaintext));
    } catch (error) {
        if (error instanceof SyntaxError) {
            throw new Error("A saved record contains invalid encrypted data.");
        }
        throw error;
    }
    if (
        typeof credential.website !== "string" ||
        typeof credential.username !== "string" ||
        typeof credential.password !== "string" ||
        typeof credential.notes !== "string"
    ) {
        throw new Error("A saved record has an invalid encrypted format.");
    }
    return {
        ...credential,
        id: record.id,
        created_at: record.created_at,
        updated_at: record.updated_at
    };
}

function randomBelow(limit) {
    const range = 0x100000000;
    const ceiling = Math.floor(range / limit) * limit;
    const sample = new Uint32Array(1);
    do {
        crypto.getRandomValues(sample);
    } while (sample[0] >= ceiling);
    return sample[0] % limit;
}

function generateStrongPassword(length) {
    const groups = [
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "!@#$%^&*()-_=+"
    ];
    const alphabet = groups.join("");
    const characters = groups.map((group) => group[randomBelow(group.length)]);
    while (characters.length < length) {
        characters.push(alphabet[randomBelow(alphabet.length)]);
    }
    for (let index = characters.length - 1; index > 0; index -= 1) {
        const swapIndex = randomBelow(index + 1);
        [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
    }
    return characters.join("");
}

function showToast(message, isError = false) {
    const toast = document.createElement("div");
    toast.className = isError ? "toast error" : "toast";
    toast.setAttribute("role", isError ? "alert" : "status");
    toast.textContent = message;
    elements.toastRegion.append(toast);
    window.setTimeout(() => toast.remove(), 4200);
}

async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body !== undefined) {
        headers.set("Content-Type", "application/json");
    }
    if (options.method && !["GET", "HEAD"].includes(options.method.toUpperCase())) {
        headers.set("X-Vault-CSRF", state.csrfToken);
    }
    let response;
    try {
        response = await fetch(path, {
            ...options,
            headers,
            credentials: "same-origin",
            cache: "no-store"
        });
    } catch (error) {
        if (error instanceof TypeError) {
            const backendOrigin = new URL(path, window.location.href).origin;
            throw new Error(
                `Cannot reach VaultPass at ${backendOrigin}. Start the server at this address and reload.`
            );
        }
        throw error;
    }
    let data = {};
    try {
        data = await response.json();
    } catch {
        if (!response.ok) {
            throw new Error("The server returned an unexpected response.");
        }
    }
    if (!response.ok) {
        if (response.status === 401 && state.csrfToken) {
            lockLocally();
        }
        const error = new Error(data.detail || "The request could not be completed.");
        error.status = response.status;
        throw error;
    }
    return data;
}

function lockLocally() {
    state.csrfToken = "";
    state.encryptionKey = null;
    state.credentials = [];
    state.editingId = null;
    state.generatedPassword = "";
    elements.credentialRows.replaceChildren();
    elements.recentList.replaceChildren();
    elements.generatedOutput.textContent = "Choose a length and generate one";
    elements.searchInput.value = "";
    if (elements.credentialDialog.open) {
        elements.credentialDialog.close();
    }
    elements.credentialPassword.value = "";
    elements.credentialNotes.value = "";
    elements.appShell.classList.add("hidden");
    elements.authScreen.classList.remove("hidden");
    setAuthMode(true);
    elements.masterPassword.value = "";
    elements.masterPassword.focus();
}

function setAuthMode(configured) {
    elements.authTitle.textContent = configured ? "Unlock your vault" : "Create your vault";
    elements.authDescription.textContent = configured
        ? "Your passwords are encrypted and only available after you unlock your vault."
        : "Choose a strong master password to create your encrypted local vault.";
    elements.authSubmit.innerHTML = configured
        ? 'Unlock vault <span aria-hidden="true">→</span>'
        : 'Create secure vault <span aria-hidden="true">→</span>';
    elements.masterPassword.autocomplete = configured ? "current-password" : "new-password";
    elements.masterPassword.minLength = configured ? 1 : 12;
    elements.setupHint.classList.toggle("hidden", configured);
}

async function loadAuthStatus() {
    try {
        const status = await api("/api/auth/status");
        state.salt = status.salt || "";
        setAuthMode(status.configured);
        elements.authScreen.classList.remove("hidden");
        elements.appShell.classList.add("hidden");
    } catch (error) {
        showToast(error.message, true);
    }
}

function enterVault(csrfToken, encryptionKey) {
    state.csrfToken = csrfToken;
    state.encryptionKey = encryptionKey;
    elements.authScreen.classList.add("hidden");
    elements.appShell.classList.remove("hidden");
    navigateTo("overview");
    return refreshCredentials();
}

async function refreshCredentials() {
    try {
        const result = await api("/api/credentials");
        state.credentials = await Promise.all(
            result.credentials.map(decryptCredentialRecord)
        );
        renderCredentials();
    } catch (error) {
        if (state.csrfToken) {
            showToast(error.message, true);
        }
    }
}

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
        element.className = className;
    }
    if (text !== undefined) {
        element.textContent = text;
    }
    return element;
}

function iconButton(label, className = "icon-button", glyph = "copy") {
    const button = makeElement("button", className);
    button.type = "button";
    button.setAttribute("aria-label", label);
    button.title = label;
    if (glyph === "copy") {
        button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>';
    } else if (glyph === "edit") {
        button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14 5 5 5M4 20l4.2-.8L19 7.4 16.6 5 5.8 15.8 5 20Z"/></svg>';
    } else if (glyph === "delete") {
        button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16m-10 4v6m4-6v6M6 7l1 14h10l1-14M9 7V4h6v3"/></svg>';
    } else if (glyph === "eye") {
        button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>';
    }
    return button;
}

function makeSiteAvatar(website) {
    const avatar = makeElement("span", "site-avatar");
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = website.trim().charAt(0).toUpperCase() || "?";
    return avatar;
}

function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return "Recently";
    }
    return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
}

function filteredCredentials() {
    const term = elements.searchInput.value.trim().toLowerCase();
    if (!term) {
        return state.credentials;
    }
    return state.credentials.filter((item) =>
        item.website.toLowerCase().includes(term) ||
        item.username.toLowerCase().includes(term)
    );
}

function renderCredentials() {
    const total = state.credentials.length;
    elements.totalCount.textContent = String(total);
    elements.navCount.textContent = String(total);
    elements.credentialRows.replaceChildren();
    elements.recentList.replaceChildren();

    const filtered = filteredCredentials();
    elements.resultCount.textContent = `${filtered.length} ${filtered.length === 1 ? "item" : "items"}`;
    elements.vaultEmpty.classList.toggle("hidden", total !== 0);
    elements.searchEmpty.classList.toggle("hidden", total === 0 || filtered.length !== 0);
    elements.tableScroll.classList.toggle("hidden", filtered.length === 0);

    for (const credential of filtered) {
        elements.credentialRows.append(createCredentialRow(credential));
    }
    for (const credential of state.credentials.slice(0, 4)) {
        elements.recentList.append(createRecentRow(credential));
    }
    if (total === 0) {
        elements.recentList.append(makeElement("div", "empty-compact", "Your saved passwords will appear here."));
    }
}

function createCredentialRow(credential) {
    const row = document.createElement("tr");

    const websiteCell = document.createElement("td");
    const website = makeElement("div", "credential-site");
    website.append(makeSiteAvatar(credential.website));
    website.append(makeElement("strong", "", credential.website));
    websiteCell.append(website);

    const usernameCell = document.createElement("td");
    const username = makeElement("div", "credential-username");
    username.append(makeElement("span", "", credential.username || "—"));
    if (credential.username) {
        const copyUsername = iconButton("Copy username", "icon-button row-copy");
        copyUsername.addEventListener("click", () => copyText(credential.username, "Username copied."));
        username.append(copyUsername);
    }
    usernameCell.append(username);

    const passwordCell = document.createElement("td");
    const password = makeElement("div", "credential-password");
    const passwordValue = makeElement("span", "", "••••••••");
    passwordValue.dataset.secret = credential.password;
    password.append(passwordValue);
    const reveal = iconButton("Show password", "icon-button row-reveal", "eye");
    reveal.addEventListener("click", () => {
        const shown = passwordValue.textContent === passwordValue.dataset.secret;
        passwordValue.textContent = shown ? "••••••••" : passwordValue.dataset.secret;
        reveal.setAttribute("aria-label", shown ? "Show password" : "Hide password");
        reveal.title = shown ? "Show password" : "Hide password";
    });
    password.append(reveal);
    const copyPassword = iconButton("Copy password", "icon-button row-copy");
    copyPassword.addEventListener("click", () => copyText(credential.password, "Password copied."));
    password.append(copyPassword);
    passwordCell.append(password);

    const dateCell = makeElement("td", "date-cell", formatDate(credential.updated_at));
    const actionsCell = document.createElement("td");
    const actions = makeElement("div", "row-actions");
    const editButton = iconButton("Edit credential", "icon-button", "edit");
    editButton.addEventListener("click", () => openCredentialDialog(credential));
    const deleteButton = iconButton("Delete credential", "icon-button row-delete", "delete");
    deleteButton.addEventListener("click", () => deleteCredential(credential));
    actions.append(editButton, deleteButton);
    actionsCell.append(actions);
    row.append(websiteCell, usernameCell, passwordCell, dateCell, actionsCell);
    return row;
}

function createRecentRow(credential) {
    const row = makeElement("div", "recent-row");
    row.append(makeSiteAvatar(credential.website));
    const info = makeElement("div", "recent-info");
    info.append(makeElement("strong", "", credential.website));
    info.append(makeElement("span", "", credential.username || "No username"));
    row.append(info);
    row.append(makeElement("span", "recent-time", formatDate(credential.updated_at)));
    row.append(makeElement("span", "recent-arrow", "›"));
    return row;
}

async function copyText(text, successMessage) {
    try {
        await navigator.clipboard.writeText(text);
        showToast(successMessage);
    } catch {
        showToast("Clipboard access is unavailable. Select and copy the value instead.", true);
    }
}

function navigateTo(view) {
    state.activeView = view;
    const pageNames = { overview: "Overview", vault: "Password vault", generator: "Password generator" };
    document.querySelectorAll(".page-view").forEach((page) => page.classList.add("hidden"));
    byId(`${view}-view`).classList.remove("hidden");
    document.querySelectorAll(".nav-item[data-view]").forEach((button) => {
        button.classList.toggle("active", button.dataset.view === view);
    });
    elements.pageCrumb.textContent = pageNames[view];
    elements.sidebar.classList.remove("open");
}

function openCredentialDialog(credential = null) {
    state.editingId = credential ? credential.id : null;
    elements.credentialForm.reset();
    elements.formError.classList.add("hidden");
    elements.dialogTitle.textContent = credential ? "Edit password" : "Add a password";
    elements.saveCredential.textContent = credential ? "Save changes" : "Save password";
    elements.credentialWebsite.value = credential ? credential.website : "";
    elements.credentialUsername.value = credential ? credential.username : "";
    elements.credentialPassword.value = credential ? credential.password : "";
    elements.credentialNotes.value = credential ? credential.notes : "";
    elements.credentialPassword.type = "password";
    if (elements.credentialDialog.showModal) {
        elements.credentialDialog.showModal();
    } else {
        elements.credentialDialog.setAttribute("open", "");
    }
    elements.credentialWebsite.focus();
}

function closeCredentialDialog() {
    if (elements.credentialDialog.open) {
        elements.credentialDialog.close();
    } else {
        elements.credentialDialog.removeAttribute("open");
    }
    elements.credentialPassword.value = "";
    elements.credentialNotes.value = "";
    state.editingId = null;
}

async function saveCredential(event) {
    event.preventDefault();
    elements.formError.classList.add("hidden");
    const website = elements.credentialWebsite.value.trim();
    const password = elements.credentialPassword.value;
    if (!website || !password) {
        elements.formError.textContent = "Website and password are required.";
        elements.formError.classList.remove("hidden");
        return;
    }
    const payload = {
        website,
        username: elements.credentialUsername.value.trim(),
        password,
        notes: elements.credentialNotes.value.trim()
    };
    const button = elements.saveCredential;
    button.disabled = true;
    try {
        const credentialId = state.editingId || crypto.randomUUID();
        const encryptedPayload = await encryptCredentialPayload(credentialId, payload);
        const result = await api(
            state.editingId ? `/api/credentials/${encodeURIComponent(state.editingId)}` : "/api/credentials",
            { method: state.editingId ? "PUT" : "POST", body: JSON.stringify(encryptedPayload) }
        );
        const message = result.message;
        closeCredentialDialog();
        await refreshCredentials();
        showToast(message);
    } catch (error) {
        elements.formError.textContent = error.message;
        elements.formError.classList.remove("hidden");
    } finally {
        button.disabled = false;
    }
}

async function deleteCredential(credential) {
    if (!window.confirm(`Delete the saved password for ${credential.website}? This cannot be undone.`)) {
        return;
    }
    try {
        const result = await api(`/api/credentials/${encodeURIComponent(credential.id)}`, { method: "DELETE" });
        await refreshCredentials();
        showToast(result.message);
    } catch (error) {
        showToast(error.message, true);
    }
}

async function requestGeneratedPassword(length) {
    return generateStrongPassword(Number(length));
}

async function generateInGenerator() {
    elements.generateButton.disabled = true;
    try {
        state.generatedPassword = await requestGeneratedPassword(elements.passwordLength.value);
        elements.generatedOutput.textContent = state.generatedPassword;
    } catch (error) {
        showToast(error.message, true);
    } finally {
        elements.generateButton.disabled = false;
    }
}

async function lockVault() {
    try {
        await api("/api/auth/lock", { method: "POST" });
        lockLocally();
        showToast("Vault locked.");
    } catch (error) {
        showToast(error.message, true);
    }
}

async function submitAuth() {
    const password = elements.masterPassword.value;
    const setup = elements.setupHint.classList.contains("hidden") === false;
    if (!password) {
        showToast("Enter your master password to continue.", true);
        elements.masterPassword.focus();
        return;
    }
    if (setup && password.length < 12) {
        showToast("Choose a master password with at least 12 characters.", true);
        return;
    }
    elements.authSubmit.disabled = true;
    try {
        const salt = setup
            ? crypto.getRandomValues(new Uint8Array(16))
            : decodeBase64(state.salt);
        const keys = await deriveVaultKeys(password, salt);
        let authPayload;
        if (setup) {
            authPayload = {
                salt: encodeBase64(salt),
                verifier: encodeBase64(keys.authVerifier)
            };
        } else {
            const challenge = await api("/api/auth/challenge");
            authPayload = {
                challenge_id: challenge.challenge_id,
                proof: await createLoginProof(
                    keys.authVerifier,
                    challenge.challenge,
                    challenge.challenge_id
                )
            };
        }
        const result = await api(setup ? "/api/auth/setup" : "/api/auth/unlock", {
            method: "POST",
            body: JSON.stringify(authPayload)
        });
        state.salt = encodeBase64(salt);
        elements.masterPassword.value = "";
        if (setup) {
            setAuthMode(true);
        }
        await enterVault(result.csrf_token, keys.encryptionKey);
        showToast(result.message);
    } catch (error) {
        showToast(error.message, true);
    } finally {
        elements.authSubmit.disabled = false;
    }
}

function setUpListeners() {
    document.querySelectorAll("[data-view]").forEach((button) => {
        button.addEventListener("click", () => navigateTo(button.dataset.view));
    });
    document.querySelectorAll("[data-add-credential]").forEach((button) => {
        button.addEventListener("click", () => openCredentialDialog());
    });
    document.querySelectorAll("[data-reveal]").forEach((button) => {
        button.addEventListener("click", () => {
            const input = byId(button.dataset.reveal);
            const showing = input.type === "text";
            input.type = showing ? "password" : "text";
            button.setAttribute("aria-pressed", String(!showing));
            button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
        });
    });
    elements.authSubmit.addEventListener("click", submitAuth);
    elements.masterPassword.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            submitAuth();
        }
    });
    elements.lockButton.addEventListener("click", lockVault);
    elements.searchInput.addEventListener("input", renderCredentials);
    elements.credentialForm.addEventListener("submit", saveCredential);
    elements.dialogClose.addEventListener("click", closeCredentialDialog);
    elements.cancelDialog.addEventListener("click", closeCredentialDialog);
    elements.credentialDialog.addEventListener("click", (event) => {
        if (event.target === elements.credentialDialog) {
            closeCredentialDialog();
        }
    });
    elements.formGenerate.addEventListener("click", async () => {
        try {
            elements.credentialPassword.value = await requestGeneratedPassword(20);
            elements.credentialPassword.type = "text";
        } catch (error) {
            showToast(error.message, true);
        }
    });
    elements.copyFormUsername.addEventListener("click", () => {
        if (elements.credentialUsername.value) {
            copyText(elements.credentialUsername.value, "Username copied.");
        } else {
            showToast("Enter a username before copying it.", true);
        }
    });
    elements.copyFormPassword.addEventListener("click", () => {
        if (elements.credentialPassword.value) {
            copyText(elements.credentialPassword.value, "Password copied.");
        } else {
            showToast("Enter or generate a password before copying it.", true);
        }
    });
    elements.passwordLength.addEventListener("input", () => {
        elements.lengthValue.textContent = elements.passwordLength.value;
    });
    elements.generateButton.addEventListener("click", generateInGenerator);
    elements.copyGenerated.addEventListener("click", () => {
        if (state.generatedPassword) {
            copyText(state.generatedPassword, "Password copied.");
        } else {
            showToast("Generate a password first.", true);
        }
    });
    elements.copyGeneratorSecondary.addEventListener("click", () => {
        if (state.generatedPassword) {
            copyText(state.generatedPassword, "Password copied.");
        } else {
            showToast("Generate a password first.", true);
        }
    });
    elements.mobileMenu.addEventListener("click", () => elements.sidebar.classList.toggle("open"));
}

document.addEventListener("DOMContentLoaded", () => {
    for (const id of [
        "toast-region", "auth-screen", "app-shell", "auth-form", "auth-title",
        "auth-description", "auth-submit", "master-password", "setup-hint",
        "total-count", "nav-count", "credential-rows", "recent-list", "result-count",
        "vault-empty", "search-empty", "table-scroll", "search-input", "page-crumb",
        "sidebar", "lock-button", "credential-dialog", "credential-form", "dialog-title",
        "save-credential", "credential-website", "credential-username",
        "credential-password", "credential-notes", "form-error", "dialog-close",
        "cancel-dialog", "form-generate", "copy-form-username", "copy-form-password",
        "password-length", "length-value", "generated-output", "generate-button",
        "copy-generated", "copy-generator-secondary", "mobile-menu"
    ]) {
        elements[camelCase(id)] = byId(id);
    }
    setUpListeners();
    loadAuthStatus();
});

function camelCase(value) {
    return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}
