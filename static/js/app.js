"use strict";

/* -------------------------------------------------------------------------
   VaultPass client
   Credentials are decrypted in the browser and never leave the tab.
   The server only ever receives AES-GCM ciphertext.
   ------------------------------------------------------------------------- */

const state = {
    csrfToken: "",
    salt: "",
    encryptionKey: null,
    credentials: [],
    editingId: null,
    activeView: "overview",
    generatedPassword: "",
    sessionExpiresAt: 0,
    searchTerm: "",
    categoryFilter: "all",
    sortOrder: "updated",
    sessionTimerId: null,
    revealTimers: new Map(),
    settings: {
        length: 20,
        revealTimeout: 30,
        density: "comfortable"
    }
};

/* Plaintext secrets are kept in memory only, never in the DOM. A WeakMap lets
   the secret disappear with the element that owns it. */
let secretStore = new WeakMap();
const MASK = "••••••••••••";

const PREFERENCE_KEY = "vaultpass.preferences.v1";
const CATEGORY_FALLBACK = "General";

const VIEW_TITLES = {
    overview: "Overview",
    credentials: "All credentials",
    favorites: "Favorites",
    generator: "Password generator",
    security: "Security center",
    settings: "Settings"
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

/* ------------------------------------------------------------- crypto --- */

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

function credentialPayload(credential) {
    return {
        website: credential.website,
        username: credential.username,
        password: credential.password,
        notes: credential.notes,
        category: credential.category,
        favorite: credential.favorite
    };
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
        typeof credential.password !== "string"
    ) {
        throw new Error("A saved record has an invalid encrypted format.");
    }
    return {
        id: record.id,
        website: credential.website,
        username: credential.username,
        password: credential.password,
        notes: typeof credential.notes === "string" ? credential.notes : "",
        category: typeof credential.category === "string" ? credential.category : "",
        favorite: credential.favorite === true,
        created_at: record.created_at,
        updated_at: record.updated_at
    };
}

/* --------------------------------------------------------- generator --- */

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

/* ----------------------------------------------------------- plumbing --- */

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

const ICONS = {
    copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>',
    edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14 5 5 5M4 20l4.2-.8L19 7.4 16.6 5 5.8 15.8 5 20Z"/></svg>',
    delete: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16m-10 4v6m4-6v6M6 7l1 14h10l1-14M9 7V4h6v3"/></svg>',
    eye: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>',
    star: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3.6 2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.5 9.8l5.9-.9L12 3.6Z"/></svg>',
    tag: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h6l2 3h8v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7Z"/><circle cx="15.5" cy="14" r="1.2"/></svg>'
};

function iconButton(label, className = "icon-button", glyph = "copy") {
    const button = makeElement("button", className);
    button.type = "button";
    button.setAttribute("aria-label", label);
    button.title = label;
    if (ICONS[glyph]) {
        button.innerHTML = ICONS[glyph];
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

function categoryOf(credential) {
    const value = (credential.category || "").trim();
    return value || CATEGORY_FALLBACK;
}

/* --------------------------------------------------------- preferences --- */

function loadPreferences() {
    try {
        const stored = window.localStorage.getItem(PREFERENCE_KEY);
        if (!stored) {
            return;
        }
        const parsed = JSON.parse(stored);
        if (Number.isInteger(parsed.length) && parsed.length >= 8 && parsed.length <= 64) {
            state.settings.length = parsed.length;
        }
        if ([0, 15, 30, 60].includes(parsed.revealTimeout)) {
            state.settings.revealTimeout = parsed.revealTimeout;
        }
        if (["comfortable", "compact"].includes(parsed.density)) {
            state.settings.density = parsed.density;
        }
    } catch (error) {
        /* Preferences are optional; ignore malformed or blocked storage. */
    }
}

function savePreferences() {
    try {
        window.localStorage.setItem(PREFERENCE_KEY, JSON.stringify(state.settings));
    } catch (error) {
        /* Storage may be unavailable in private modes; preferences stay in memory. */
    }
}

function applyPreferences() {
    document.body.classList.toggle("density-compact", state.settings.density === "compact");
    elements.settingLength.value = String(state.settings.length);
    elements.settingRevealTimeout.value = String(state.settings.revealTimeout);
    elements.settingDensity.value = state.settings.density;
    elements.passwordLength.value = String(state.settings.length);
    elements.lengthValue.textContent = String(state.settings.length);
}

/* ------------------------------------------------------------- session --- */

function startSessionTimer() {
    if (state.sessionTimerId) {
        window.clearInterval(state.sessionTimerId);
        state.sessionTimerId = null;
    }
    if (!state.sessionExpiresAt) {
        elements.sessionTimer.textContent = "--:--";
        elements.settingsSessionTimer.textContent = "--:--";
        return;
    }
    const update = () => {
        const remaining = Math.max(0, state.sessionExpiresAt - Math.floor(Date.now() / 1000));
        const label = `${String(Math.floor(remaining / 60)).padStart(2, "0")}:${String(remaining % 60).padStart(2, "0")}`;
        elements.sessionTimer.textContent = label;
        elements.settingsSessionTimer.textContent = label;
    };
    update();
    state.sessionTimerId = window.setInterval(update, 1000);
}

/* --------------------------------------------------------------- auth --- */

function setAuthMode(configured) {
    elements.authTitle.textContent = "One vault. Every password. Peace of mind.";
    elements.authDescription.textContent = configured
        ? "Keep your credentials protected in one secure place with a clean, local-first vault experience."
        : "Keep your digital credentials organized in one place with a security-focused password manager built for privacy.";
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

function enterVault(csrfToken, encryptionKey, expiresAt) {
    state.csrfToken = csrfToken;
    state.encryptionKey = encryptionKey;
    state.sessionExpiresAt = Number(expiresAt) || 0;
    elements.authScreen.classList.add("hidden");
    elements.appShell.classList.remove("hidden");
    startSessionTimer();
    navigateTo("overview");
    renderSkeletons();
    return refreshCredentials();
}

function lockLocally() {
    state.csrfToken = "";
    state.encryptionKey = null;
    state.credentials = [];
    state.editingId = null;
    state.generatedPassword = "";
    state.searchTerm = "";
    state.categoryFilter = "all";
    state.sessionExpiresAt = 0;
    if (state.sessionTimerId) {
        window.clearInterval(state.sessionTimerId);
        state.sessionTimerId = null;
    }
    for (const timer of state.revealTimers.values()) {
        window.clearTimeout(timer);
    }
    state.revealTimers.clear();
    secretStore = new WeakMap();
    elements.credentialRows.replaceChildren();
    elements.recentList.replaceChildren();
    elements.favoritesList.replaceChildren();
    elements.attentionList.replaceChildren();
    elements.generatedOutput.textContent = "Choose a length and generate one";
    elements.globalSearch.value = "";
    elements.clearSearch.classList.add("hidden");
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
        await enterVault(result.csrf_token, keys.encryptionKey, result.expires_at);
        showToast(result.message);
    } catch (error) {
        showToast(error.message, true);
    } finally {
        elements.authSubmit.disabled = false;
    }
}

async function lockVault() {
    try {
        const result = await api("/api/auth/lock", { method: "POST" });
        lockLocally();
        showToast(result.message || "Vault locked.");
    } catch (error) {
        showToast(error.message, true);
    }
}

/* ----------------------------------------------------------- rendering --- */

function renderSkeletons() {
    elements.recentList.replaceChildren();
    for (let index = 0; index < 4; index += 1) {
        const card = makeElement("div", "credential-card skeleton-card");
        const head = makeElement("div", "credential-card-head");
        const avatar = makeElement("span", "skeleton site-avatar");
        const identity = makeElement("div", "credential-identity");
        const line = makeElement("span", "skeleton line");
        identity.append(line);
        const meta = makeElement("span", "skeleton line short");
        identity.append(meta);
        head.append(avatar, identity);
        card.append(head);
        const foot = makeElement("div", "credential-card-foot");
        foot.append(makeElement("span", "skeleton line"));
        card.append(foot);
        elements.recentList.append(card);
    }
}

function filteredCredentials() {
    const term = state.searchTerm.trim().toLowerCase();
    let result = state.credentials.filter((item) => {
        if (state.categoryFilter !== "all" && categoryOf(item) !== state.categoryFilter) {
            return false;
        }
        if (!term) {
            return true;
        }
        return (
            item.website.toLowerCase().includes(term) ||
            item.username.toLowerCase().includes(term) ||
            categoryOf(item).toLowerCase().includes(term)
        );
    });
    const sorted = [...result];
    sorted.sort((first, second) => {
        switch (state.sortOrder) {
            case "name":
                return first.website.localeCompare(second.website);
            case "created":
                return String(second.created_at).localeCompare(String(first.created_at));
            case "category":
                return categoryOf(first).localeCompare(categoryOf(second)) ||
                    first.website.localeCompare(second.website);
            default:
                return String(second.updated_at).localeCompare(String(first.updated_at));
        }
    });
    return sorted;
}

function renderMetrics() {
    const total = state.credentials.length;
    const favorites = state.credentials.filter((item) => item.favorite).length;
    const categories = new Set(state.credentials.map(categoryOf)).size;
    const strong = state.credentials.filter((item) => isStrongPassword(item.password)).length;

    elements.totalCount.textContent = String(total);
    elements.favoriteCount.textContent = String(favorites);
    elements.categoryCount.textContent = String(categories);
    elements.strongCount.textContent = String(strong);
    elements.strongFoot.textContent = total
        ? `${strong} of ${total} use 16+ mixed characters`
        : "16+ characters with mixed classes";
    elements.navCount.textContent = String(total);
    elements.navFavorites.textContent = String(favorites);
    elements.heroPrimaryLabel.textContent = total
        ? "Add a credential"
        : "Add your first credential";
}

function renderCategoryOptions() {
    const categories = [...new Set(state.credentials.map(categoryOf))].sort((a, b) => a.localeCompare(b));
    const current = state.categoryFilter;
    elements.categoryFilter.replaceChildren();
    const all = document.createElement("option");
    all.value = "all";
    all.textContent = "All categories";
    elements.categoryFilter.append(all);
    for (const category of categories) {
        const option = document.createElement("option");
        option.value = category;
        option.textContent = category;
        elements.categoryFilter.append(option);
    }
    elements.categoryFilter.value = categories.includes(current) ? current : "all";
    state.categoryFilter = elements.categoryFilter.value;

    const suggestions = elements.categorySuggestions;
    suggestions.replaceChildren();
    for (const category of categories) {
        const option = document.createElement("option");
        option.value = category;
        suggestions.append(option);
    }
}

function makePasswordField(credential, className) {
    const wrapper = makeElement("div", className);
    const value = makeElement("span", "", MASK);
    secretStore.set(value, credential.password);
    const reveal = iconButton("Show password", "icon-button row-reveal", "eye");
    reveal.addEventListener("click", () => toggleReveal(value, reveal));
    const copy = iconButton("Copy password", "icon-button row-copy");
    copy.addEventListener("click", () => copyText(credential.password, "Password copied."));
    wrapper.append(value, reveal, copy);
    return wrapper;
}

function toggleReveal(valueElement, button) {
    const secret = secretStore.get(valueElement);
    if (secret === undefined) {
        return;
    }
    const isRevealed = valueElement.textContent === secret;
    if (isRevealed) {
        valueElement.textContent = MASK;
        button.setAttribute("aria-label", "Show password");
        button.title = "Show password";
        const timer = state.revealTimers.get(valueElement);
        if (timer) {
            window.clearTimeout(timer);
            state.revealTimers.delete(valueElement);
        }
        return;
    }
    valueElement.textContent = secret;
    button.setAttribute("aria-label", "Hide password");
    button.title = "Hide password";
    if (state.settings.revealTimeout > 0) {
        const timer = window.setTimeout(() => {
            valueElement.textContent = MASK;
            button.setAttribute("aria-label", "Show password");
            button.title = "Show password";
            state.revealTimers.delete(valueElement);
        }, state.settings.revealTimeout * 1000);
        state.revealTimers.set(valueElement, timer);
    }
}

function makeStarButton(credential) {
    const star = iconButton(
        credential.favorite ? "Remove from favorites" : "Add to favorites",
        "star-button",
        "star"
    );
    star.setAttribute("aria-pressed", credential.favorite ? "true" : "false");
    star.addEventListener("click", async () => {
        star.disabled = true;
        try {
            await updateStoredCredential(credential, {
                favorite: !credential.favorite
            });
            showToast(credential.favorite
                ? "Removed from favorites."
                : "Added to favorites.");
        } catch (error) {
            showToast(error.message, true);
        } finally {
            star.disabled = false;
        }
    });
    return star;
}

function makeCategoryChip(credential) {
    const chip = makeElement("span", "category-chip");
    chip.innerHTML = ICONS.tag;
    chip.append(makeElement("span", "", categoryOf(credential)));
    return chip;
}

function createCredentialCard(credential) {
    const card = makeElement("article", "credential-card");

    const head = makeElement("div", "credential-card-head");
    head.append(makeSiteAvatar(credential.website));
    const identity = makeElement("div", "credential-identity");
    identity.append(makeElement("strong", "", credential.website));
    identity.append(makeElement("span", "", credential.username || "No username"));
    head.append(identity);
    head.append(makeStarButton(credential));
    card.append(head);

    const meta = makeElement("div", "credential-card-meta");
    meta.append(makeCategoryChip(credential));
    meta.append(makeElement("span", "credential-updated", `Updated ${formatDate(credential.updated_at)}`));
    card.append(meta);

    const foot = makeElement("div", "credential-card-foot");
    foot.append(makePasswordField(credential, "password-field"));

    const actions = makeElement("div", "credential-actions");
    const copyUsername = iconButton("Copy username", "icon-button");
    copyUsername.addEventListener("click", () => {
        if (credential.username) {
            copyText(credential.username, "Username copied.");
        } else {
            showToast("This credential has no username.", true);
        }
    });
    const editButton = iconButton("Edit credential", "icon-button", "edit");
    editButton.addEventListener("click", () => openCredentialDialog(credential));
    const deleteButton = iconButton("Delete credential", "icon-button row-delete", "delete");
    deleteButton.addEventListener("click", () => deleteCredential(credential));
    actions.append(copyUsername, editButton, deleteButton);
    foot.append(actions);
    card.append(foot);

    return card;
}

function createCredentialRow(credential) {
    const row = document.createElement("tr");

    const websiteCell = document.createElement("td");
    const website = makeElement("div", "credential-site");
    website.append(makeSiteAvatar(credential.website));
    website.append(makeElement("strong", "", credential.website));
    website.append(makeStarButton(credential));
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
    passwordCell.append(makePasswordField(credential, "credential-password"));

    const categoryCell = document.createElement("td");
    categoryCell.append(makeCategoryChip(credential));

    const dateCell = makeElement("td", "date-cell", formatDate(credential.updated_at));

    const actionsCell = document.createElement("td");
    const actions = makeElement("div", "row-actions");
    const editButton = iconButton("Edit credential", "icon-button", "edit");
    editButton.addEventListener("click", () => openCredentialDialog(credential));
    const deleteButton = iconButton("Delete credential", "icon-button row-delete", "delete");
    deleteButton.addEventListener("click", () => deleteCredential(credential));
    actions.append(editButton, deleteButton);
    actionsCell.append(actions);

    row.append(websiteCell, usernameCell, passwordCell, categoryCell, dateCell, actionsCell);
    return row;
}

function renderRecent() {
    const total = state.credentials.length;
    const filtered = filteredCredentials();
    const recent = filtered.slice(0, 6);

    elements.recentList.replaceChildren();
    for (const credential of recent) {
        elements.recentList.append(createCredentialCard(credential));
    }

    if (total === 0) {
        elements.recentEmpty.classList.remove("hidden");
        elements.recentEmptyTitle.textContent = "Your vault is ready for its first secret";
        elements.recentEmptyText.textContent =
            "Add a credential and it will appear here, encrypted and retrievable in seconds.";
        elements.recentEmptyAction.textContent = "Add your first credential";
        elements.recentEmptyAction.hidden = false;
    } else if (recent.length === 0) {
        elements.recentEmpty.classList.remove("hidden");
        elements.recentEmptyTitle.textContent = "No matching credentials";
        elements.recentEmptyText.textContent =
            "Try a different website, username, or category.";
        elements.recentEmptyAction.hidden = true;
    } else {
        elements.recentEmpty.classList.add("hidden");
    }
}

function renderFavorites() {
    const favorites = filteredCredentials().filter((item) => item.favorite);
    elements.favoritesList.replaceChildren();
    for (const credential of favorites) {
        elements.favoritesList.append(createCredentialCard(credential));
    }
    elements.favoritesEmpty.classList.toggle("hidden", favorites.length !== 0);
    elements.favoritesList.classList.toggle("hidden", favorites.length === 0);
}

function renderTable() {
    const total = state.credentials.length;
    const filtered = filteredCredentials();

    elements.credentialRows.replaceChildren();
    for (const credential of filtered) {
        elements.credentialRows.append(createCredentialRow(credential));
    }
    elements.resultCount.textContent = `${filtered.length} ${filtered.length === 1 ? "item" : "items"}`;
    elements.vaultEmpty.classList.toggle("hidden", total !== 0);
    elements.searchEmpty.classList.toggle("hidden", total === 0 || filtered.length !== 0);
    elements.tableScroll.classList.toggle("hidden", filtered.length === 0);
}

function isStrongPassword(password) {
    if (typeof password !== "string" || password.length < 16) {
        return false;
    }
    return (
        /[a-z]/.test(password) &&
        /[A-Z]/.test(password) &&
        /[0-9]/.test(password) &&
        /[^A-Za-z0-9]/.test(password)
    );
}

function analyzeVault() {
    const usage = new Map();
    for (const credential of state.credentials) {
        const list = usage.get(credential.password) || [];
        list.push(credential);
        usage.set(credential.password, list);
    }
    const reused = new Set();
    for (const [, list] of usage) {
        if (list.length > 1) {
            for (const credential of list) {
                reused.add(credential.id);
            }
        }
    }
    const strong = state.credentials.filter((item) => isStrongPassword(item.password));
    const weak = state.credentials.filter((item) => !isStrongPassword(item.password));
    const attention = state.credentials
        .filter((item) => !isStrongPassword(item.password) || reused.has(item.id))
        .sort((first, second) => {
            const firstReused = reused.has(first.id) ? 1 : 0;
            const secondReused = reused.has(second.id) ? 1 : 0;
            return secondReused - firstReused;
        });
    const updated = state.credentials
        .map((item) => item.updated_at)
        .filter(Boolean)
        .sort()
        .pop();
    return { strong, weak, reused, attention, updated };
}

function renderSecurity() {
    const analysis = analyzeVault();
    elements.securityStrong.textContent = String(analysis.strong.length);
    elements.securityStrongFoot.textContent = analysis.strong.length
        ? `${analysis.strong.length} of ${state.credentials.length} records`
        : "16+ characters, mixed classes";
    elements.securityWeak.textContent = String(analysis.weak.length);
    elements.securityReused.textContent = String(analysis.reused.size);
    elements.securityUpdated.textContent = analysis.updated ? formatDate(analysis.updated) : "—";

    elements.attentionList.replaceChildren();
    for (const credential of analysis.attention) {
        const item = makeElement("div", "attention-item");
        item.append(makeSiteAvatar(credential.website));
        const text = makeElement("div", "attention-text");
        text.append(makeElement("strong", "", credential.website));
        text.append(makeElement("span", "", credential.username || "No username"));
        item.append(text);
        const reused = analysis.reused.has(credential.id);
        const tag = makeElement("span", `attention-tag ${reused ? "reused" : "weak"}`,
                reused ? "Reused password" : "Weak password");
        item.append(tag);
        const fix = makeElement("button", "button button-secondary", "Update");
        fix.type = "button";
        fix.addEventListener("click", () => openCredentialDialog(credential));
        item.append(fix);
        elements.attentionList.append(item);
    }
    elements.attentionCount.textContent = String(analysis.attention.length);
    elements.attentionEmpty.classList.toggle("hidden", analysis.attention.length !== 0);
    elements.attentionList.classList.toggle("hidden", analysis.attention.length === 0);

    const snapshot = elements.securitySnapshot;
    if (state.credentials.length === 0) {
        snapshot.textContent =
            "Add a few credentials and VaultPass will analyse them for weak and reused passwords.";
    } else {
        snapshot.textContent =
            `${analysis.strong.length} of ${state.credentials.length} credentials use a strong password. ` +
            `${analysis.weak.length} need attention, ${analysis.reused.size} reused across sites.`;
    }
}

function renderAll() {
    renderMetrics();
    renderCategoryOptions();
    renderRecent();
    renderFavorites();
    renderTable();
    renderSecurity();
}

/* ------------------------------------------------------------- actions --- */

async function copyText(text, successMessage) {
    if (!text) {
        showToast("There is nothing to copy.", true);
        return;
    }
    try {
        await navigator.clipboard.writeText(text);
        showToast(successMessage);
    } catch {
        showToast("Clipboard access is unavailable. Select and copy the value instead.", true);
    }
}

async function updateStoredCredential(credential, changes) {
    const payload = credentialPayload({ ...credential, ...changes });
    const encrypted = await encryptCredentialPayload(credential.id, payload);
    const result = await api(`/api/credentials/${encodeURIComponent(credential.id)}`, {
        method: "PUT",
        body: JSON.stringify(encrypted)
    });
    await refreshCredentials();
    return result;
}

async function refreshCredentials() {
    try {
        const result = await api("/api/credentials");
        const settled = await Promise.allSettled(
            result.credentials.map(decryptCredentialRecord)
        );
        state.credentials = settled
            .filter((item) => item.status === "fulfilled")
            .map((item) => item.value);
        const failed = settled.filter((item) => item.status === "rejected");
        renderAll();
        if (failed.length) {
            showToast(
                `${failed.length} saved ${failed.length === 1 ? "record" : "records"} could not be decrypted and ${failed.length === 1 ? "was" : "were"} skipped.`,
                true
            );
        }
    } catch (error) {
        if (state.csrfToken) {
            showToast(error.message, true);
            renderAll();
        }
    }
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
    elements.credentialCategory.value = credential ? (credential.category || "") : "";
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
    const existing = state.credentials.find((item) => item.id === state.editingId);
    const payload = {
        website,
        username: elements.credentialUsername.value.trim(),
        password,
        notes: elements.credentialNotes.value.trim(),
        category: elements.credentialCategory.value.trim(),
        favorite: existing ? existing.favorite : false
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
        closeCredentialDialog();
        await refreshCredentials();
        showToast(result.message);
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

async function generateInGenerator() {
    elements.generateButton.disabled = true;
    try {
        state.generatedPassword = generateStrongPassword(Number(elements.passwordLength.value));
        elements.generatedOutput.textContent = state.generatedPassword;
    } catch (error) {
        showToast(error.message, true);
    } finally {
        elements.generateButton.disabled = false;
    }
}

/* ---------------------------------------------------------- navigation --- */

function navigateTo(view) {
    const target = byId(`${view}-view`);
    if (!target) {
        return;
    }
    state.activeView = view;
    document.querySelectorAll(".page-view").forEach((page) => page.classList.add("hidden"));
    target.classList.remove("hidden");
    document.querySelectorAll(".nav-item[data-view]").forEach((button) => {
        button.classList.toggle("active", button.dataset.view === view);
    });
    closeSidebar();
    closeProfileMenu();
    window.scrollTo({ top: 0, behavior: "smooth" });
}

function openSidebar() {
    elements.sidebar.classList.add("open");
    elements.sidebarScrim.classList.add("visible");
    elements.mobileMenu.setAttribute("aria-expanded", "true");
}

function closeSidebar() {
    elements.sidebar.classList.remove("open");
    elements.sidebarScrim.classList.remove("visible");
    elements.mobileMenu.setAttribute("aria-expanded", "false");
}

function openProfileMenu() {
    elements.profileMenu.classList.remove("hidden");
    elements.profileButton.setAttribute("aria-expanded", "true");
}

function closeProfileMenu() {
    elements.profileMenu.classList.add("hidden");
    elements.profileButton.setAttribute("aria-expanded", "false");
}

function applySearch(term) {
    state.searchTerm = term;
    elements.clearSearch.classList.toggle("hidden", term.length === 0);
    renderRecent();
    renderFavorites();
    renderTable();
    renderSecurity();
}

/* ------------------------------------------------------------ listeners --- */

function setUpListeners() {
    document.querySelectorAll("[data-view]").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.preventDefault();
            navigateTo(button.dataset.view);
        });
    });

    document.querySelectorAll("[data-add-credential]").forEach((button) => {
        button.addEventListener("click", () => openCredentialDialog());
    });

    document.querySelectorAll("[data-lock-now]").forEach((button) => {
        button.addEventListener("click", () => lockVault());
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
    elements.profileLock.addEventListener("click", lockVault);
    elements.profileButton.addEventListener("click", (event) => {
        event.stopPropagation();
        if (elements.profileMenu.classList.contains("hidden")) {
            openProfileMenu();
        } else {
            closeProfileMenu();
        }
    });
    document.addEventListener("click", (event) => {
        if (!event.target.closest(".profile-wrap")) {
            closeProfileMenu();
        }
    });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeProfileMenu();
            closeSidebar();
        }
    });

    elements.mobileMenu.addEventListener("click", () => {
        if (elements.sidebar.classList.contains("open")) {
            closeSidebar();
        } else {
            openSidebar();
        }
    });
    elements.sidebarClose.addEventListener("click", closeSidebar);
    elements.sidebarScrim.addEventListener("click", closeSidebar);

    elements.globalSearch.addEventListener("input", (event) => applySearch(event.target.value));
    elements.clearSearch.addEventListener("click", () => {
        elements.globalSearch.value = "";
        applySearch("");
        elements.globalSearch.focus();
    });

    elements.categoryFilter.addEventListener("change", (event) => {
        state.categoryFilter = event.target.value;
        renderRecent();
        renderFavorites();
        renderTable();
    });
    elements.sortSelect.addEventListener("change", (event) => {
        state.sortOrder = event.target.value;
        renderTable();
    });

    elements.credentialForm.addEventListener("submit", saveCredential);
    elements.dialogClose.addEventListener("click", closeCredentialDialog);
    elements.cancelDialog.addEventListener("click", closeCredentialDialog);
    elements.credentialDialog.addEventListener("click", (event) => {
        if (event.target === elements.credentialDialog) {
            closeCredentialDialog();
        }
    });

    elements.formGenerate.addEventListener("click", () => {
        try {
            elements.credentialPassword.value = generateStrongPassword(state.settings.length);
            elements.credentialPassword.type = "text";
        } catch (error) {
            showToast(error.message, true);
        }
    });
    elements.copyFormUsername.addEventListener("click", () => {
        copyText(elements.credentialUsername.value.trim(), "Username copied.");
    });
    elements.copyFormPassword.addEventListener("click", () => {
        copyText(elements.credentialPassword.value, "Password copied.");
    });

    elements.passwordLength.addEventListener("input", () => {
        elements.lengthValue.textContent = elements.passwordLength.value;
    });
    elements.generateButton.addEventListener("click", generateInGenerator);
    elements.copyGenerated.addEventListener("click", () => {
        copyText(state.generatedPassword, "Password copied.");
    });
    elements.copyGeneratorSecondary.addEventListener("click", () => {
        copyText(state.generatedPassword, "Password copied.");
    });

    elements.settingLength.addEventListener("change", (event) => {
        const value = Number(event.target.value);
        if (!Number.isInteger(value) || value < 8 || value > 64) {
            return;
        }
        state.settings.length = value;
        elements.passwordLength.value = String(value);
        elements.lengthValue.textContent = String(value);
        savePreferences();
    });
    elements.settingRevealTimeout.addEventListener("change", (event) => {
        const value = Number(event.target.value);
        if (![0, 15, 30, 60].includes(value)) {
            return;
        }
        state.settings.revealTimeout = value;
        savePreferences();
    });
    elements.settingDensity.addEventListener("change", (event) => {
        const value = event.target.value;
        if (!["comfortable", "compact"].includes(value)) {
            return;
        }
        state.settings.density = value;
        document.body.classList.toggle("density-compact", value === "compact");
        savePreferences();
    });
}

/* ---------------------------------------------------------------- boot --- */

document.addEventListener("DOMContentLoaded", () => {
    const ids = [
        "toast-region", "auth-screen", "app-shell", "auth-title", "auth-description",
        "auth-submit", "master-password", "setup-hint",
        "total-count", "favorite-count", "category-count", "strong-count", "strong-foot",
        "nav-count", "nav-favorites",
        "credential-rows", "recent-list", "recent-empty", "recent-empty-title",
        "recent-empty-text", "recent-empty-action", "favorites-list", "favorites-empty",
        "result-count", "vault-empty", "search-empty", "table-scroll",
        "global-search", "clear-search", "category-filter", "sort-select",
        "sidebar", "sidebar-scrim", "sidebar-close", "mobile-menu",
        "lock-button", "profile-button", "profile-menu", "profile-lock",
        "session-timer", "settings-session-timer",
        "credential-dialog", "credential-form", "dialog-title", "save-credential",
        "credential-website", "credential-username", "credential-password",
        "credential-notes", "credential-category", "category-suggestions",
        "form-error", "dialog-close", "cancel-dialog", "form-generate",
        "copy-form-username", "copy-form-password",
        "password-length", "length-value", "generated-output", "generate-button",
        "copy-generated", "copy-generator-secondary",
        "setting-length", "setting-reveal-timeout", "setting-density",
        "security-strong", "security-weak", "security-reused", "security-updated",
        "security-strong-foot", "attention-list", "attention-empty", "attention-count",
        "security-snapshot", "hero-primary-label"
    ];
    for (const id of ids) {
        elements[id.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = byId(id);
    }
    loadPreferences();
    applyPreferences();
    setUpListeners();
    loadAuthStatus();
});
