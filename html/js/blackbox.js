// Modernized secure digital vault JS
window.currentUser = "";
window.sessionPassword = null; // kept in memory for the session; still needed to decrypt legacy (pre-MEK) files
window.sessionMEK = null; // unwrapped master encryption key (CryptoKey) for the session - wraps/unwraps per-file keys
window.activePreviewBlob = null;
window.activePreviewName = "";

// Must stay in sync with .config.MAXUPLOAD on the server (cap on the base64-encoded payload)
const MAX_UPLOAD_BASE64_BYTES = 2 * 1024 * 1024 * 1024;
// Raw (pre-base64) bytes encoded and sent per websocket chunk during upload. Must be a
// multiple of 3 so every chunk's base64 encoding is padding-free on its own - only the
// final chunk may be short and padded. This lets each chunk be base64-encoded
// independently (never materializing the whole file as one JS string, which blows past
// the ~1GB engine string-length limit for large files) while still re-assembling into a
// valid base64 stream server-side.
const CHUNK_SIZE = 1536 * 1024;
// Salt used by files uploaded before per-file salts existed (backward compatibility)
const LEGACY_SALT = new TextEncoder().encode("BlackBoxClientSaltForPBKDF2");

let allFiles = [];
let activeCategory = "All";
let currentAction = null;
let inactivityTimeout = null;
// Correlates the single in-flight request/response pair for chunked upload and
// download-token exchanges, which the server answers with a typed message rather
// than a direct reply. Only one such exchange runs at a time (buttons are guarded).
let pendingResponse = null;

// ============================== UTILS ============================ //
const getInputVal = (elemid) => document.getElementById(elemid).value;

const notifyUser = (msgObj) => {
    const toast = document.getElementById("notificationToast");
    const head = document.getElementById("dialogHead");
    const body = document.getElementById("dialogBody");

    head.textContent = msgObj.head || "Notification";
    body.textContent = msgObj.body || "";

    toast.classList.remove("hide");

    clearTimeout(window.toastTimeout);
    window.toastTimeout = setTimeout(() => {
        toast.classList.add("hide");
    }, 4000);
};

const toggleServerBusy = (status) => {
    const overlay = document.getElementById("overlay");
    if (status) {
        overlay.classList.remove("hide");
    } else {
        overlay.classList.add("hide");
    }
};

const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

// ============================== BASE64 HELPERS ============================ //
// Converted in chunks (rather than one JS loop over every byte) and yielding to the
// event loop between chunks - large files (100s of MB) would otherwise block the main
// thread for seconds and freeze the tab.
const BASE64_CHUNK_BYTES = 0x8000; // fromCharCode.apply's argument-count limit

const bufferToBase64 = async (buffer) => {
    const bytes = new Uint8Array(buffer);
    const parts = [];
    for (let i = 0; i < bytes.length; i += BASE64_CHUNK_BYTES) {
        parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + BASE64_CHUNK_BYTES)));
        if (i % (BASE64_CHUNK_BYTES * 200) === 0) await new Promise((r) => setTimeout(r, 0));
    }
    return window.btoa(parts.join(''));
};

const base64ToBuffer = async (base64) => {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
        if (i % (BASE64_CHUNK_BYTES * 200) === 0) await new Promise((r) => setTimeout(r, 0));
    }
    return bytes.buffer;
};

// ============================== CRYPTO SYSTEM ============================ //
const deriveKeyFromPassword = async (password, salt) => {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

const encryptData = async (arrayBuffer, cryptoKey) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        arrayBuffer
    );
    return {
        encryptedData,
        iv: await bufferToBase64(iv)
    };
};

const decryptData = async (encryptedArrayBuffer, cryptoKey, ivBase64) => {
    const iv = new Uint8Array(await base64ToBuffer(ivBase64));
    return crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        encryptedArrayBuffer
    );
};

// Derive the AES key for a file from the session password and the file's own salt.
// An empty salt means the file predates per-file salts, so fall back to the legacy salt.
// Only used for files that predate the master-key-envelope scheme below (no fileKeyWrapped).
const deriveKeyForSalt = async (saltBase64) => {
    const salt = saltBase64 ? new Uint8Array(await base64ToBuffer(saltBase64)) : LEGACY_SALT;
    return deriveKeyFromPassword(window.sessionPassword, salt);
};

// ============================== KEY WRAPPING (MEK) ============================ //
// Every file is encrypted with its own random key (FK). FK is itself encrypted ("wrapped")
// with a per-user Master Encryption Key (MEK), which is generated once and never changes.
// The MEK is wrapped with a key derived from the login password (KEK) and stored server-side
// only in that wrapped form. Changing the password only needs to re-wrap the MEK (see
// wrapMEK/submitChangePassword) - every file's wrapped FK, and so every file, stays readable.
const generateMEK = () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

// Wrap a MEK CryptoKey (freshly generated, or the session's existing one when changing
// password) with a KEK derived from `password`. Returns the envelope to send to the server.
const wrapMEK = async (mekKey, password) => {
    const rawMek = await crypto.subtle.exportKey("raw", mekKey);
    const wrapSalt = crypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKeyFromPassword(password, wrapSalt);
    const { encryptedData, iv } = await encryptData(rawMek, kek);
    return {
        mek: await bufferToBase64(encryptedData),
        mekIv: iv,
        wrapSalt: await bufferToBase64(wrapSalt.buffer)
    };
};

// Unwrap a stored MEK envelope using `password`. Throws (AES-GCM auth failure) if the
// envelope was wrapped under a different password - e.g. an admin reset the password via
// the console without knowing the old one, orphaning the previous envelope.
const unwrapMEK = async (password, mekBase64, mekIvBase64, wrapSaltBase64) => {
    const wrapSalt = new Uint8Array(await base64ToBuffer(wrapSaltBase64));
    const kek = await deriveKeyFromPassword(password, wrapSalt);
    const wrapped = await base64ToBuffer(mekBase64);
    const rawMek = await decryptData(wrapped, kek, mekIvBase64);
    return crypto.subtle.importKey("raw", rawMek, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
};

// Generate a fresh per-file key and wrap it with the session MEK, for a new upload.
const generateAndWrapFileKey = async () => {
    const fkKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const rawFk = await crypto.subtle.exportKey("raw", fkKey);
    const { encryptedData, iv } = await encryptData(rawFk, window.sessionMEK);
    return { fkKey, fileKeyWrapped: await bufferToBase64(encryptedData), fileKeyIv: iv };
};

// Unwrap a file's key using the session MEK, for download/preview.
const unwrapFileKey = async (fileKeyWrappedBase64, fileKeyIvBase64) => {
    const wrapped = await base64ToBuffer(fileKeyWrappedBase64);
    const rawFk = await decryptData(wrapped, window.sessionMEK, fileKeyIvBase64);
    return crypto.subtle.importKey("raw", rawFk, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
};

// ============================== MD5 / CHALLENGE-RESPONSE LOGIN ============================ //
// Web Crypto has no MD5 (browsers dropped it from SubtleCrypto). The server's stored auth
// hash is q's iterated-salted-MD5 (.util.hashPass in util.q, unchanged), so logging in
// without ever sending the password means the browser has to speak the same MD5-based
// scheme. This is a plain RFC 1321 implementation, verified byte-for-byte against Node's
// crypto module and against q's native md5 (including RFC edge cases and multi-block
// messages) before being wired into the login path.
const md5 = (bytes) => {
    const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = new Int32Array(64);
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;

    const msgLenBits = BigInt(bytes.length) * 8n;
    const padLen = (56 - (bytes.length + 1) % 64 + 64) % 64;
    const padded = new Uint8Array(bytes.length + 1 + padLen + 8);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    new DataView(padded.buffer, padded.length - 8, 8).setBigUint64(0, msgLenBits, true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const rotl = (x, c) => (x << c) | (x >>> (32 - c));

    for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
        const M = new Int32Array(16);
        const dv = new DataView(padded.buffer, chunkStart, 64);
        for (let j = 0; j < 16; j++) M[j] = dv.getInt32(j * 4, true);

        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F, g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * i) % 16; }
            F = (F + A + K[i] + M[g]) | 0;
            A = D; D = C; C = B;
            B = (B + rotl(F, s[i])) | 0;
        }
        a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }

    const out = new Uint8Array(16);
    const outView = new DataView(out.buffer);
    outView.setInt32(0, a0, true);
    outView.setInt32(4, b0, true);
    outView.setInt32(8, c0, true);
    outView.setInt32(12, d0, true);
    return out;
};

const md5ToHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");

// Mirrors .util.hashPass in kx/q/util.q exactly: r=pass; repeat 100000x: r=hex(md5(salt+r)).
// Must stay byte-for-byte identical to the q side, or nobody can log in.
const hashPass = (salt, pass) => {
    const enc = new TextEncoder();
    let r = pass;
    for (let i = 0; i < 100000; i++) {
        r = md5ToHex(md5(enc.encode(salt + r)));
    }
    return r;
};

// Standard HMAC construction over MD5 (64-byte block size) - mirrors .util.hmacMd5 in
// util.q. Proves the client knows the same stored auth hash the server has, without ever
// sending the password (or the hash) itself.
const hmacMd5 = (keyStr, msgStr) => {
    const enc = new TextEncoder();
    let key = enc.encode(keyStr);
    if (key.length > 64) key = md5(key);
    const padded = new Uint8Array(64);
    padded.set(key);
    const ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { ipad[i] = padded[i] ^ 0x36; opad[i] = padded[i] ^ 0x5c; }
    const msg = enc.encode(msgStr);
    const inner = new Uint8Array(64 + msg.length);
    inner.set(ipad); inner.set(msg, 64);
    const innerHash = md5(inner);
    const outer = new Uint8Array(64 + 16);
    outer.set(opad); outer.set(innerHash, 64);
    return md5ToHex(md5(outer));
};

// The auth key (AK) is whatever's stored server-side as the passphrase hash - salted
// .util.hashPass normally, or a single unsalted md5 round for an account that predates
// salted hashing (empty salt, same convention used for legacy file keys elsewhere).
const authKeyFor = (salt, pass) => (salt ? hashPass(salt, pass) : md5ToHex(md5(new TextEncoder().encode(pass))));

// ============================== AUTH FLOW ============================ //
const authUser = () => {
    const modal = document.getElementById("authModal");
    modal.classList.remove("hide");
    document.getElementById("logoutBtn").classList.add("hide");
    document.getElementById("changePasswordBtn").classList.add("hide");
    document.getElementById("usernameInput").focus();
};

// The password itself never goes over the wire, not even at login: request a single-use
// challenge, prove knowledge of the stored auth hash via HMAC-MD5(AK, nonce), and send only
// that proof. See the MD5/CHALLENGE-RESPONSE section above for why HMAC-MD5 rather than
// real SRP (q has no SHA-256/bignum to build that on).
const submitAuth = async () => {
    const userinp = document.getElementById("usernameInput").value.trim();
    const userpass = document.getElementById("passwordInput").value;

    if (!userinp || !userpass) {
        notifyUser({ head: "Error", body: "Please enter both username and passphrase." });
        return;
    }

    window.tempPassword = userpass;

    document.querySelector(".modal-body").classList.add("hide");
    document.getElementById("authSpinner").classList.remove("hide");

    try {
        const chal = await sendCorrelated("getAuthChallenge", { userid: userinp });
        const ak = authKeyFor(chal.salt, userpass);
        const proof = hmacMd5(ak, chal.nonce);
        // Stashed for handleAuth to pick up post-login: an empty challenge salt means this
        // account predates salted hashing and should be upgraded now that we've proven we
        // know the password (authUser itself can no longer do this transparently - the
        // server never sees the plaintext to re-hash).
        window._loginWasLegacy = !chal.salt;
        socket.sendCmd("authUser", { userid: userinp, nonce: chal.nonce, proof: proof });
    } catch (e) {
        console.error("Login challenge failed:", e);
        document.querySelector(".modal-body").classList.remove("hide");
        document.getElementById("authSpinner").classList.add("hide");
        notifyUser({ head: "Error", body: "Could not reach the server to log in. Try again." });
    }
};

// Get the session MEK ready: unwrap the one the server has, or bootstrap a fresh one if
// this is the account's first browser login, or if the stored envelope no longer opens
// with this password (e.g. an admin reset the password via the console without knowing
// the old one - the old envelope is orphaned, so a new key covers files uploaded from here).
const ensureSessionMEK = async (resp) => {
    if (resp.mek) {
        try {
            window.sessionMEK = await unwrapMEK(window.sessionPassword, resp.mek, resp.mekIv, resp.wrapSalt);
            return;
        } catch (e) {
            console.error("MEK unwrap failed - password changed outside this browser?", e);
            notifyUser({
                head: "Key Recovery Needed",
                body: "Your master key couldn't be unlocked with this password. A new one was created - files uploaded since your last password change may be unreadable."
            });
        }
    }
    const mekKey = await generateMEK();
    const wrapped = await wrapMEK(mekKey, window.sessionPassword);
    window.sessionMEK = mekKey;
    await sendCorrelated("setMEK", wrapped);
};

// One-time upgrade for an account that just logged in via the legacy (pre-salt) auth
// scheme: now that we've proven knowledge of the password via the challenge, derive a
// proper salted hash and push it up. Best-effort - a failure here just means the account
// stays on the legacy scheme until the next successful login retries it.
const upgradeLegacyAuthIfNeeded = async () => {
    if (!window._loginWasLegacy) return;
    window._loginWasLegacy = false;
    try {
        const newSaltBytes = crypto.getRandomValues(new Uint8Array(16));
        const newSalt = await bufferToBase64(newSaltBytes.buffer);
        const newHash = hashPass(newSalt, window.sessionPassword);
        await sendCorrelated("upgradeLegacyAuth", { newHash, newSalt });
    } catch (e) {
        console.error("Legacy auth upgrade failed (non-fatal):", e);
    }
};

const handleAuth = async (resp) => {
    document.querySelector(".modal-body").classList.remove("hide");
    document.getElementById("authSpinner").classList.add("hide");

    if (!resp || !resp.ok) {
        notifyUser({ head: "Authentication Failed", body: "Not authorised. Try again." });
        document.getElementById("passwordInput").value = "";
        window.tempPassword = null;
        document.getElementById("usernameInput").focus();
    } else {
        console.log("Authentication successful");
        window.currentUser = document.getElementById("usernameInput").value.trim();

        // Keep the password in memory for the session - still needed to decrypt any legacy
        // (pre-MEK) files, since those derive their key from the password directly.
        window.sessionPassword = window.tempPassword;
        window.tempPassword = null;

        try {
            await ensureSessionMEK(resp);
            await upgradeLegacyAuthIfNeeded();
        } catch (e) {
            console.error("Failed to set up master key:", e);
            notifyUser({ head: "Error", body: "Could not set up encryption for this session. Try logging in again." });
            document.getElementById("authModal").classList.remove("hide");
            return;
        }

        document.getElementById("authModal").classList.add("hide");
        document.getElementById("logoutBtn").classList.remove("hide");
        document.getElementById("changePasswordBtn").classList.remove("hide");
        document.getElementById("passwordInput").value = "";

        notifyUser({ head: "Success", body: "Successfully authenticated!" });

        startInactivityTimer();

        socket.sendCmd("recentUploadsForUser", { userid: window.currentUser });
        socket.sendCmd("getSystemStats", { userid: window.currentUser });
    }
};

const logout = () => {
    window.currentUser = "";
    window.sessionPassword = null;
    window.sessionMEK = null;
    window.activePreviewBlob = null;
    window.activePreviewName = "";
    allFiles = [];

    document.getElementById("filesList").innerHTML = '<div class="no-files">No files uploaded yet.</div>';
    document.getElementById("storageUsed").textContent = "0 B";
    document.getElementById("storageProgressBar").style.width = "0%";

    closePreviewModal();
    stopInactivityTimer();
    authUser();
};

// ============================== CHANGE PASSWORD ============================ //
const openChangePassword = () => {
    document.getElementById("changePasswordModal").classList.remove("hide");
    document.getElementById("currentPasswordInput").focus();
};

const closeChangePassword = () => {
    document.getElementById("changePasswordModal").classList.add("hide");
    document.getElementById("currentPasswordInput").value = "";
    document.getElementById("newPasswordInput").value = "";
    document.getElementById("confirmPasswordInput").value = "";
};

const submitChangePassword = async () => {
    const currentPassword = document.getElementById("currentPasswordInput").value;
    const newPassword = document.getElementById("newPasswordInput").value;
    const confirmPassword = document.getElementById("confirmPasswordInput").value;

    if (!currentPassword || !newPassword) {
        notifyUser({ head: "Error", body: "Please fill in all fields." });
        return;
    }
    if (newPassword !== confirmPassword) {
        notifyUser({ head: "Error", body: "New passwords don't match." });
        return;
    }
    if (currentPassword !== window.sessionPassword) {
        notifyUser({ head: "Error", body: "Current passphrase is incorrect." });
        return;
    }
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    try {
        // Re-wrap the SAME session MEK under the new password - not a new one, or every
        // file encrypted so far would become unreadable.
        const wrapped = await wrapMEK(window.sessionMEK, newPassword);
        // The new password never crosses the wire either - send the already-salted-and-
        // hashed auth verifier (same derivation authUser checks against), not the plaintext.
        const newAuthSaltBytes = crypto.getRandomValues(new Uint8Array(16));
        const newSalt = await bufferToBase64(newAuthSaltBytes.buffer);
        const newHash = hashPass(newSalt, newPassword);
        await sendCorrelated("changePassword", {
            newHash: newHash,
            newSalt: newSalt,
            newMek: wrapped.mek,
            newMekIv: wrapped.mekIv,
            newWrapSalt: wrapped.wrapSalt
        });
        window.sessionPassword = newPassword;
        closeChangePassword();
        notifyUser({ head: "Password Changed", body: "Your password has been updated. All files remain accessible." });
    } catch (e) {
        console.error(e);
        notifyUser({ head: "Error", body: e.message || "Failed to change password." });
    } finally {
        toggleServerBusy(false);
    }
};

// ============================== INACTIVITY LOCK ============================ //
const startInactivityTimer = () => {
    stopInactivityTimer();
    inactivityTimeout = setTimeout(() => {
        notifyUser({ head: "Session Locked", body: "Logged out due to 5 minutes of inactivity." });
        logout();
    }, 5 * 60 * 1000); // 5 minutes
};

const stopInactivityTimer = () => {
    if (inactivityTimeout) {
        clearTimeout(inactivityTimeout);
        inactivityTimeout = null;
    }
};

const resetInactivityTimer = () => {
    if (window.currentUser) {
        startInactivityTimer();
    }
};

const initInactivityMonitor = () => {
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
        window.addEventListener(event, resetInactivityTimer);
    });
};

// ============================== LOGIC ================================= //
const updUsersOnline = (data) => {
    const elem = document.getElementById('numUsers');
    elem.textContent = data.numusers || 0;
};

const updateRecentUploads = (files) => {
    allFiles = Array.isArray(files) ? files : (files ? [files] : []);
    filterFiles();
};

const updateSystemStats = (stats) => {
    const used = stats.used || 0;
    const capacity = stats.capacity || 68719476736;

    document.getElementById("storageUsed").textContent = formatBytes(used);
    document.getElementById("storageCapacity").textContent = formatBytes(capacity);

    const percentage = Math.min(100, (used / capacity) * 100);
    document.getElementById("storageProgressBar").style.width = `${percentage}%`;
};

// ============================== FILTER & SEARCH ============================ //
const selectCategoryTab = (btn) => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeCategory = btn.getAttribute("data-category");
    filterFiles();
};

const filterFiles = () => {
    const searchVal = document.getElementById("searchInput").value.toLowerCase().trim();
    const listElem = document.getElementById("filesList");
    if (!listElem) return;

    listElem.innerHTML = "";

    const filtered = allFiles.filter(file => {
        if (!file) return false;

        // Filter by Category
        if (activeCategory !== "All" && file.category !== activeCategory) {
            return false;
        }

        // Filter by Search Query
        if (searchVal) {
            const nameMatch = file.fileName.toLowerCase().includes(searchVal);
            const tagMatch = file.tags && file.tags.toLowerCase().includes(searchVal);
            return nameMatch || tagMatch;
        }

        return true;
    });

    if (filtered.length === 0) {
        listElem.innerHTML = '<div class="no-files">No files match your search criteria.</div>';
        return;
    }

    filtered.forEach(file => {
        const item = document.createElement("div");
        item.className = "file-item";

        const info = document.createElement("div");
        info.className = "file-info";

        const icon = document.createElement("i");
        icon.className = getFileIcon(file.mimeType);

        const textWrapper = document.createElement("div");

        const name = document.createElement("span");
        name.className = "file-name";
        name.textContent = file.fileName;
        name.title = file.fileName;

        textWrapper.appendChild(name);

        // Display tags
        if (file.tags) {
            const tagsList = document.createElement("div");
            tagsList.className = "file-tags-list";
            file.tags.split(",").forEach(t => {
                const badge = document.createElement("span");
                badge.className = "tag-badge";
                badge.textContent = t.trim();
                tagsList.appendChild(badge);
            });
            textWrapper.appendChild(tagsList);
        }

        info.appendChild(icon);
        info.appendChild(textWrapper);

        const actions = document.createElement("div");
        actions.className = "file-actions";

        // Preview Button
        const previewBtn = document.createElement("button");
        previewBtn.className = "file-action-btn";
        previewBtn.innerHTML = '<i class="ph ph-eye"></i>';
        previewBtn.title = "Preview File";
        previewBtn.onclick = () => {
            if (!isPreviewableMime(file.mimeType)) {
                showUnsupportedPreview(file.fileid, file.fileName);
                return;
            }
            currentAction = "preview";
            downloadFile(file.fileid);
        };

        // Download Button
        const downloadBtn = document.createElement("button");
        downloadBtn.className = "file-action-btn";
        downloadBtn.innerHTML = '<i class="ph ph-download-simple"></i>';
        downloadBtn.title = "Download File";
        downloadBtn.onclick = () => {
            currentAction = "download";
            downloadFile(file.fileid);
        };

        // Delete Button
        const deleteBtn = document.createElement("button");
        deleteBtn.className = "file-action-btn file-action-danger";
        deleteBtn.innerHTML = '<i class="ph ph-trash"></i>';
        deleteBtn.title = "Delete File";
        deleteBtn.onclick = () => deleteFile(file.fileid, file.fileName);

        actions.appendChild(previewBtn);
        actions.appendChild(downloadBtn);
        actions.appendChild(deleteBtn);

        item.appendChild(info);
        item.appendChild(actions);
        listElem.appendChild(item);
    });
};

// Single source of truth for what showPreview can actually render - checked against
// metadata already in hand so unsupported types never trigger a download+decrypt.
const isPreviewableMime = (mimeType) =>
    mimeType.startsWith("image/") || mimeType === "application/pdf" || mimeType.startsWith("text/");

const getFileIcon = (mimeType) => {
    if (!mimeType) return "ph ph-file";
    if (mimeType.startsWith("image/")) return "ph ph-file-image";
    if (mimeType === "application/pdf") return "ph ph-file-pdf";
    if (mimeType.startsWith("text/")) return "ph ph-file-text";
    return "ph ph-file";
};

// ============================== UPLOAD ================================= //
const readFile = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => resolve(event.target.result);
        reader.onerror = (error) => reject(error);
        reader.readAsArrayBuffer(file);
    });
};

// Sends one command and resolves/rejects when the correlated response arrives (see connect.js).
const sendCorrelated = (cmd, params) => new Promise((resolve, reject) => {
    pendingResponse = { resolve, reject };
    socket.sendCmd(cmd, params);
});

const buildTags = (file, userTags) => {
    const fileExtension = file.name.split('.').pop().toLowerCase();
    const autoTags = [];

    if (file.type.startsWith("image/")) {
        autoTags.push("image");
    } else if (file.type === "application/json" || fileExtension === "json") {
        autoTags.push("json");
    } else if (file.type === "text/csv" || fileExtension === "csv") {
        autoTags.push("csv");
    } else if (file.type === "application/pdf" || fileExtension === "pdf") {
        autoTags.push("pdf");
        autoTags.push("document");
    } else if (["doc", "docx", "txt", "rtf", "odt"].includes(fileExtension)) {
        autoTags.push("document");
        if (fileExtension === "txt") autoTags.push("text");
    }

    return [...new Set([...userTags, ...autoTags])].join(", ");
};

const showUploadProgress = (visible) => {
    const el = document.getElementById("uploadProgress");
    if (!el) return;
    el.classList.toggle("hide", !visible);
    if (!visible) document.getElementById("uploadProgressBar").style.width = "0%";
};

const updateUploadProgress = (index, total, fileName, pct) => {
    const label = document.getElementById("uploadProgressLabel");
    const bar = document.getElementById("uploadProgressBar");
    if (!label || !bar) return;
    label.textContent = total > 1
        ? `Uploading ${index + 1} of ${total}: ${fileName} (${pct}%)`
        : `Uploading ${fileName} (${pct}%)`;
    bar.style.width = `${pct}%`;
};

// Encrypts one file, then streams the ciphertext to the server in CHUNK_SIZE pieces
// so a single file never has to fit in one websocket/JSON message.
const uploadOneFile = async (file, category, userTags, index, total) => {
    updateUploadProgress(index, total, file.name, 0);

    const arrayBuffer = await readFile(file);
    const { fkKey, fileKeyWrapped, fileKeyIv } = await generateAndWrapFileKey();
    const { encryptedData, iv } = await encryptData(arrayBuffer, fkKey);
    const encryptedBytes = new Uint8Array(encryptedData);
    // Computed rather than measured off a real base64 string - see CHUNK_SIZE comment.
    const base64Length = Math.ceil(encryptedBytes.length / 3) * 4;

    if (base64Length > MAX_UPLOAD_BASE64_BYTES) {
        throw new Error(`File is too large. Maximum size is ${formatBytes(MAX_UPLOAD_BASE64_BYTES)}.`);
    }

    const combinedTags = buildTags(file, userTags);

    const startResp = await sendCorrelated("startUpload", {
        fileName: file.name,
        mimeType: file.type || "application/octet-stream",
        fileSize: base64Length,
        category: category,
        tags: combinedTags,
        iv: iv,
        salt: "", // unused for new uploads - key comes wrapped via fileKeyWrapped/MEK instead
        fileKeyWrapped: fileKeyWrapped,
        fileKeyIv: fileKeyIv
    });
    const fileid = startResp.fileid;

    const totalChunks = Math.max(1, Math.ceil(encryptedBytes.length / CHUNK_SIZE));
    for (let c = 0; c < totalChunks; c++) {
        const rawChunk = encryptedBytes.subarray(c * CHUNK_SIZE, (c + 1) * CHUNK_SIZE);
        const chunk = await bufferToBase64(rawChunk);
        await sendCorrelated("uploadChunk", { fileid, chunkData: chunk });
        updateUploadProgress(index, total, file.name, Math.round(((c + 1) / totalChunks) * 100));
    }

    await sendCorrelated("finishUpload", { fileid });
};

const uploadFiles = async () => {
    const fileInput = document.getElementById("file");
    const files = Array.from(fileInput.files || []);

    if (!files.length) {
        notifyUser({ head: "Upload Error", body: "Please select a file first." });
        return;
    }
    if (!window.sessionPassword || !window.sessionMEK) {
        notifyUser({ head: "Encryption Error", body: "Not authenticated. Cannot encrypt file." });
        return;
    }
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    const category = document.getElementById("fileCategory").value;
    const userTagsInput = document.getElementById("fileTags").value;
    const userTags = userTagsInput ? userTagsInput.split(",").map(t => t.trim()).filter(t => t) : [];

    showUploadProgress(true);
    let failures = 0;
    for (let i = 0; i < files.length; i++) {
        try {
            await uploadOneFile(files[i], category, userTags, i, files.length);
        } catch (e) {
            console.error(e);
            failures++;
            notifyUser({ head: "Upload Error", body: `Failed to upload ${files[i].name}: ${e.message}` });
        }
    }
    showUploadProgress(false);

    fileInput.value = "";
    document.getElementById("fileTags").value = "";
    document.getElementById("fileCategory").value = "Other";

    if (failures === 0 && files.length > 1) {
        notifyUser({ head: "Batch Complete", body: `All ${files.length} files uploaded successfully.` });
    }
};

// ============================== DOWNLOAD & PREVIEW HANDLERS ================================= //
// Fetches ciphertext over a plain HTTP GET (bypassing the JSON/websocket round trip) using a
// short-lived, single-use token minted by the server, then decrypts it exactly as before.
const downloadFile = async (fileid) => {
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    try {
        const tokenResp = await sendCorrelated("getDownloadToken", { fileid });
        const url = `/download?fileid=${encodeURIComponent(tokenResp.fileid)}&token=${encodeURIComponent(tokenResp.token)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const base64Data = await res.text();

        await handleDownloadResp({
            fileid: tokenResp.fileid,
            fileName: tokenResp.fileName,
            mimeType: tokenResp.mimeType,
            iv: tokenResp.iv,
            salt: tokenResp.salt,
            fileKeyWrapped: tokenResp.fileKeyWrapped,
            fileKeyIv: tokenResp.fileKeyIv,
            fileData: base64Data
        });
    } catch (e) {
        console.error(e);
        notifyUser({ head: "Download Error", body: e.message || "Failed to download file." });
    } finally {
        toggleServerBusy(false);
    }
};

const deleteFile = (fileid, fileName) => {
    if (!confirm(`Permanently delete "${fileName}"? This cannot be undone.`)) return;
    toggleServerBusy(true);
    socket.sendCmd("deleteFile", { fileid: fileid });
};

const handleDownloadResp = async (msgData) => {
    if (!window.sessionPassword) {
        notifyUser({ head: "Error", body: "Not authenticated. Cannot decrypt." });
        toggleServerBusy(false);
        return;
    }

    try {
        const fileKey = msgData.fileKeyWrapped
            ? await unwrapFileKey(msgData.fileKeyWrapped, msgData.fileKeyIv)
            : await deriveKeyForSalt(msgData.salt);
        const encryptedBuffer = await base64ToBuffer(msgData.fileData);
        const decryptedBuffer = await decryptData(encryptedBuffer, fileKey, msgData.iv);

        if (currentAction === "download") {
            const blob = new Blob([decryptedBuffer], { type: msgData.mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = msgData.fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            notifyUser({ head: "Download Success", body: `${msgData.fileName} downloaded successfully.` });
        } else if (currentAction === "preview") {
            showPreview(msgData.fileName, msgData.mimeType, decryptedBuffer);
        }
    } catch (err) {
        console.error("Decryption error:", err);
        notifyUser({ head: "Decryption Failed", body: "Failed to decrypt file payload. Authentication issue?" });
    } finally {
        toggleServerBusy(false);
    }
};

// Used when the file's mimeType isn't previewable - never fetches/decrypts the file.
const showUnsupportedPreview = (fileid, fileName) => {
    document.getElementById("previewModal").classList.remove("hide");
    document.getElementById("previewTitle").textContent = fileName;

    const body = document.getElementById("previewBody");
    body.innerHTML = "";
    window.activePreviewBlob = null;
    window.activePreviewName = fileName;

    const notice = document.createElement("p");
    notice.textContent = "Preview not supported for this file type. You can download the decrypted file.";
    notice.style.color = "var(--text-secondary)";
    body.appendChild(notice);

    const dlBtn = document.getElementById("previewDownloadBtn");
    dlBtn.onclick = () => {
        currentAction = "download";
        downloadFile(fileid);
    };
};

const showPreview = (fileName, mimeType, arrayBuffer) => {
    document.getElementById("previewModal").classList.remove("hide");
    document.getElementById("previewTitle").textContent = fileName;

    const body = document.getElementById("previewBody");
    body.innerHTML = "";

    // Store preview blob globally for download button
    window.activePreviewBlob = new Blob([arrayBuffer], { type: mimeType });
    window.activePreviewName = fileName;

    if (mimeType.startsWith("image/")) {
        const url = URL.createObjectURL(window.activePreviewBlob);
        const img = document.createElement("img");
        img.src = url;
        body.appendChild(img);
    } else if (mimeType === "application/pdf") {
        const url = URL.createObjectURL(window.activePreviewBlob);
        const iframe = document.createElement("iframe");
        iframe.src = url;
        body.appendChild(iframe);
    } else if (mimeType.startsWith("text/")) {
        const decoder = new TextDecoder();
        const text = decoder.decode(arrayBuffer);
        const pre = document.createElement("pre");
        pre.textContent = text;
        body.appendChild(pre);
    } else {
        const notice = document.createElement("p");
        notice.textContent = "Preview not supported for this file type. You can download the decrypted file.";
        notice.style.color = "var(--text-secondary)";
        body.appendChild(notice);
    }

    // Setup Download button inside preview
    const dlBtn = document.getElementById("previewDownloadBtn");
    dlBtn.onclick = () => {
        if (!window.activePreviewBlob) return;
        const url = URL.createObjectURL(window.activePreviewBlob);
        const a = document.createElement("a");
        a.href = url;
        a.download = window.activePreviewName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
};

const closePreviewModal = () => {
    document.getElementById("previewModal").classList.add("hide");
    document.getElementById("previewBody").innerHTML = "";
    window.activePreviewBlob = null;
    window.activePreviewName = "";
};

// ============================== DRAG & DROP ================================= //
const initDragAndDrop = () => {
    const dropZone = document.getElementById("uploadContainer");
    if (!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-active'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-active'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        const fileInput = document.getElementById("file");
        fileInput.files = files;
        if (files.length) uploadFiles();
    }, false);
};

const initEnterToLogin = () => {
    const passInput = document.getElementById("passwordInput");
    if (passInput) {
        passInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                submitAuth();
            }
        });
    }
};

const checkSecureContext = () => {
    if (!window.crypto || !window.crypto.subtle) {
        const warning = document.createElement("div");
        warning.style.position = "fixed";
        warning.style.top = "0";
        warning.style.left = "0";
        warning.style.width = "100%";
        warning.style.height = "100%";
        warning.style.background = "rgba(11, 12, 16, 0.95)";
        warning.style.color = "white";
        warning.style.display = "flex";
        warning.style.flexDirection = "column";
        warning.style.alignItems = "center";
        warning.style.justifyContent = "center";
        warning.style.zIndex = "9999";
        warning.style.padding = "2rem";
        warning.style.textAlign = "center";
        warning.style.fontFamily = "Inter, sans-serif";

        warning.innerHTML = `
            <i class="ph ph-warning-octagon" style="font-size: 4rem; color: #ff061f; margin-bottom: 1.5rem;"></i>
            <h2 style="margin-bottom: 1rem;">Insecure Context Detected</h2>
            <p style="color: #8b949e; max-width: 500px; line-height: 1.6; margin-bottom: 1.5rem;">
                Browser security rules disable encryption APIs (Web Crypto) on insecure connections.<br><br>
                Please access BlackBox using <strong>http://localhost:50667/index.html</strong> or <strong>http://127.0.0.1:50667/index.html</strong>.
            </p>
        `;
        document.body.appendChild(warning);
    }
};

// ============================== INIT ============================== //
window.onload = () => {
    checkSecureContext();
    window.scrollTo(0, 0);
    initDragAndDrop();
    initEnterToLogin();
    initInactivityMonitor();
    socket = connect();
    document.addEventListener("deviceready", () => {
        if (typeof onDeviceReady === 'function') onDeviceReady();
    }, false);
};
