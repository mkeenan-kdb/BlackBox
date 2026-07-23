// Modernized secure digital vault JS
window.currentUser = "";
window.isAdmin = false;
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
// Current folder drill-down, e.g. ["Documents","Tax"] for a "Documents/Tax" tag prefix.
// Folders aren't a real schema feature - any tag containing "/" is treated as a path.
let activeFolderPath = [];
let currentAction = null;
const selectedFileIds = new Set();
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

// ============================== THUMBNAILS ============================ //
const THUMBNAIL_MAX_DIMENSION = 200;

// Downscales an image client-side to a small JPEG for the file grid. PDFs are left on their
// existing icon - real PDF thumbnails need an actual PDF renderer (no browser-native path),
// and pulling in something like pdf.js is a real dependency this no-build-step app doesn't
// otherwise carry. Returns an ArrayBuffer, or null for anything that isn't an image / fails
// to decode (never blocks the upload - a missing thumbnail just means the icon shows).
const generateThumbnail = (file) => {
    if (!file.type || !file.type.startsWith("image/")) return Promise.resolve(null);

    return new Promise((resolve) => {
        const img = new Image();
        const objectUrl = URL.createObjectURL(file);

        img.onload = () => {
            let { width, height } = img;
            if (width > height) {
                if (width > THUMBNAIL_MAX_DIMENSION) { height = Math.round(height * THUMBNAIL_MAX_DIMENSION / width); width = THUMBNAIL_MAX_DIMENSION; }
            } else if (height > THUMBNAIL_MAX_DIMENSION) {
                width = Math.round(width * THUMBNAIL_MAX_DIMENSION / height); height = THUMBNAIL_MAX_DIMENSION;
            }

            const canvas = document.createElement("canvas");
            canvas.width = width;
            canvas.height = height;
            canvas.getContext("2d").drawImage(img, 0, 0, width, height);
            URL.revokeObjectURL(objectUrl);

            canvas.toBlob((blob) => {
                if (!blob) { resolve(null); return; }
                blob.arrayBuffer().then(resolve).catch(() => resolve(null));
            }, "image/jpeg", 0.7);
        };
        img.onerror = () => { URL.revokeObjectURL(objectUrl); resolve(null); };
        img.src = objectUrl;
    });
};

// Decrypted thumbnails are cached per fileid as object URLs so re-rendering the list (search,
// tab switch, folder navigation) doesn't re-decrypt every time. Never persisted - cleared on
// logout along with everything else in memory.
const thumbnailUrlCache = new Map();

const getThumbnailUrl = async (file) => {
    if (!file.thumbnail) return null;
    if (thumbnailUrlCache.has(file.fileid)) return thumbnailUrlCache.get(file.fileid);

    try {
        const fileKey = file.fileKeyWrapped
            ? await unwrapFileKey(file.fileKeyWrapped, file.fileKeyIv)
            : await deriveKeyForSalt(file.salt);
        const encryptedBuffer = await base64ToBuffer(file.thumbnail);
        const decryptedBuffer = await decryptData(encryptedBuffer, fileKey, file.thumbnailIv);
        const url = URL.createObjectURL(new Blob([decryptedBuffer], { type: "image/jpeg" }));
        thumbnailUrlCache.set(file.fileid, url);
        return url;
    } catch (e) {
        console.error("Thumbnail decrypt failed:", e);
        return null;
    }
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
    document.getElementById("adminBtn").classList.add("hide");
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
        window.isAdmin = !!resp.isAdmin;

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
        document.getElementById("adminBtn").classList.toggle("hide", !window.isAdmin);
        document.getElementById("passwordInput").value = "";

        notifyUser({ head: "Success", body: "Successfully authenticated!" });

        startInactivityTimer();

        socket.sendCmd("recentUploadsForUser", { userid: window.currentUser });
        socket.sendCmd("getSystemStats", { userid: window.currentUser });
    }
};

const logout = () => {
    window.currentUser = "";
    window.isAdmin = false;
    window.sessionPassword = null;
    window.sessionMEK = null;
    window.activePreviewBlob = null;
    window.activePreviewName = "";
    allFiles = [];
    thumbnailUrlCache.forEach((url) => URL.revokeObjectURL(url));
    thumbnailUrlCache.clear();

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

// ============================== ADMIN: USER MANAGEMENT ============================ //
const openAdminPanel = async () => {
    document.getElementById("adminModal").classList.remove("hide");
    await refreshAdminUserList();
};

const closeAdminPanel = () => {
    document.getElementById("adminModal").classList.add("hide");
    document.getElementById("newUserIdInput").value = "";
    document.getElementById("newUserPasswordInput").value = "";
    document.getElementById("newUserConfirmInput").value = "";
};

const refreshAdminUserList = async () => {
    const body = document.getElementById("adminUserListBody");
    body.innerHTML = "";
    const loading = document.createElement("p");
    loading.textContent = "Loading...";
    body.appendChild(loading);

    try {
        const resp = await sendCorrelated("adminListUsers", {});
        const users = Array.isArray(resp) ? resp : (resp ? [resp] : []);
        body.innerHTML = "";

        users.forEach((u) => {
            const row = document.createElement("div");
            row.className = "file-item";

            const info = document.createElement("div");
            info.className = "file-info";
            const label = document.createElement("span");
            label.className = "file-name";
            label.textContent = u.userid;
            info.appendChild(label);
            if (u.isAdmin) {
                const badge = document.createElement("span");
                badge.className = "tag-badge";
                badge.textContent = "admin";
                info.appendChild(badge);
            }
            const stats = document.createElement("span");
            stats.className = "folder-item-count";
            stats.textContent = `${u.numFiles} file${u.numFiles === 1 ? "" : "s"}, ${formatBytes(u.totalSize)}`;
            info.appendChild(stats);
            row.appendChild(info);

            const actions = document.createElement("div");
            actions.className = "file-actions";
            if (u.userid !== window.currentUser) {
                const delBtn = document.createElement("button");
                delBtn.className = "file-action-btn file-action-danger";
                delBtn.innerHTML = '<i class="ph ph-trash"></i>';
                delBtn.title = "Delete account";
                delBtn.onclick = () => adminDeleteUserConfirm(u.userid, u.numFiles);
                actions.appendChild(delBtn);
            }
            row.appendChild(actions);

            body.appendChild(row);
        });
    } catch (e) {
        console.error(e);
        body.innerHTML = "";
        const notice = document.createElement("p");
        notice.textContent = "Failed to load user list.";
        body.appendChild(notice);
    }
};

// The new user's password never crosses the wire, even here - this browser computes the
// salted auth hash locally (same derivation the server checks logins against) and sends
// only that. The new account's MEK bootstraps itself on their own first login, same as a
// console-created account already does.
const submitCreateUser = async () => {
    const userid = document.getElementById("newUserIdInput").value.trim();
    const password = document.getElementById("newUserPasswordInput").value;
    const confirm = document.getElementById("newUserConfirmInput").value;

    if (!userid || !password) {
        notifyUser({ head: "Error", body: "Please fill in all fields." });
        return;
    }
    if (password !== confirm) {
        notifyUser({ head: "Error", body: "Passwords don't match." });
        return;
    }
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    try {
        const newSaltBytes = crypto.getRandomValues(new Uint8Array(16));
        const newSalt = await bufferToBase64(newSaltBytes.buffer);
        const newHash = hashPass(newSalt, password);
        await sendCorrelated("adminCreateUser", { userid, newHash, newSalt });
        document.getElementById("newUserIdInput").value = "";
        document.getElementById("newUserPasswordInput").value = "";
        document.getElementById("newUserConfirmInput").value = "";
        notifyUser({ head: "User Created", body: `Account "${userid}" is ready to log in.` });
        await refreshAdminUserList();
    } catch (e) {
        console.error(e);
        notifyUser({ head: "Error", body: e.message || "Failed to create user." });
    } finally {
        toggleServerBusy(false);
    }
};

const adminDeleteUserConfirm = async (userid, numFiles) => {
    const warning = numFiles
        ? `Permanently delete "${userid}" and all ${numFiles} of their file(s)? This cannot be undone.`
        : `Permanently delete "${userid}"? This cannot be undone.`;
    if (!confirm(warning)) return;
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    try {
        await sendCorrelated("adminDeleteUser", { userid });
        notifyUser({ head: "User Deleted", body: `Account "${userid}" and their files have been removed.` });
        await refreshAdminUserList();
    } catch (e) {
        console.error(e);
        notifyUser({ head: "Error", body: e.message || "Failed to delete user." });
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

// ============================== FOLDERS (hierarchical tags) ============================ //
// Not a real schema feature - any tag containing "/" (e.g. "Documents/Tax/2026") is treated
// as a folder path. Purely client-side: parsed out of the same free-text tags every file
// already has, so no server or storage changes are needed.
const fileTagList = (file) => (file && file.tags ? file.tags.split(",").map((t) => t.trim()) : []);
const folderTagsOf = (file) => fileTagList(file).filter((t) => t.includes("/"));

const allFolderTags = () => {
    const set = new Set();
    allFiles.forEach((f) => folderTagsOf(f).forEach((t) => set.add(t)));
    return Array.from(set);
};

// Immediate child folder names one level below `path` (e.g. path=["Documents"] and a tag
// "Documents/Tax/2026" exists -> "Tax" is a child; "2026" is not, it's a grandchild).
const childFoldersAt = (path) => {
    const prefix = path.length ? path.join("/") + "/" : "";
    const children = new Set();
    allFolderTags().forEach((tag) => {
        if (path.length && !tag.startsWith(prefix)) return;
        const rest = tag.slice(prefix.length);
        if (rest) children.add(rest.split("/")[0]);
    });
    return Array.from(children).sort();
};

// Exact-match, not prefix: a file shows at a given folder level only if it has a folder tag
// exactly equal to that path (or, at the root, no folder tag at all). This is what makes
// navigation feel like a real file browser - a deeply nested file doesn't flatten into every
// ancestor level, you have to actually drill into the folder that directly contains it.
const fileMatchesFolderPath = (file) => {
    const folderTags = folderTagsOf(file);
    if (!activeFolderPath.length) return folderTags.length === 0;
    return folderTags.includes(activeFolderPath.join("/"));
};

// How many files live at-or-below `path` - shown on each folder row, like a real file browser.
const countFilesUnder = (path) => {
    const p = path.join("/");
    return allFiles.filter((f) => f && fileTagList(f).some((t) => t === p || t.startsWith(p + "/"))).length;
};

const renderFolderBreadcrumb = () => {
    const nav = document.getElementById("folderNav");
    if (!nav) return;

    if (!allFolderTags().length) {
        nav.classList.add("hide");
        return;
    }
    nav.classList.remove("hide");

    const breadcrumb = document.getElementById("folderBreadcrumb");
    breadcrumb.innerHTML = "";

    const rootCrumb = document.createElement("span");
    rootCrumb.className = "folder-crumb" + (activeFolderPath.length === 0 ? " active" : "");
    rootCrumb.innerHTML = '<i class="ph ph-folders"></i> All Folders';
    rootCrumb.onclick = () => { activeFolderPath = []; filterFiles(); };
    breadcrumb.appendChild(rootCrumb);

    activeFolderPath.forEach((seg, i) => {
        const sep = document.createElement("span");
        sep.className = "folder-sep";
        sep.textContent = "/";
        breadcrumb.appendChild(sep);

        const crumb = document.createElement("span");
        crumb.className = "folder-crumb" + (i === activeFolderPath.length - 1 ? " active" : "");
        crumb.textContent = seg;
        crumb.onclick = () => { activeFolderPath = activeFolderPath.slice(0, i + 1); filterFiles(); };
        breadcrumb.appendChild(crumb);
    });
};

// A folder as an actual row in the list (not just a filter chip above it) - click it to
// descend, same gesture as clicking into a real file browser directory.
const renderFolderRow = (name) => {
    const childPath = [...activeFolderPath, name];

    const item = document.createElement("div");
    item.className = "file-item folder-row";
    item.onclick = () => { activeFolderPath = childPath; filterFiles(); };

    const info = document.createElement("div");
    info.className = "file-info";

    const icon = document.createElement("i");
    icon.className = "ph-fill ph-folder";
    info.appendChild(icon);

    const label = document.createElement("span");
    label.className = "file-name";
    label.textContent = name;
    info.appendChild(label);

    const n = countFilesUnder(childPath);
    const count = document.createElement("span");
    count.className = "folder-item-count";
    count.textContent = `${n} item${n === 1 ? "" : "s"}`;
    info.appendChild(count);

    item.appendChild(info);

    const chevron = document.createElement("i");
    chevron.className = "ph ph-caret-right folder-chevron";
    item.appendChild(chevron);

    return item;
};

const filterFiles = () => {
    renderFolderBreadcrumb();

    const searchVal = document.getElementById("searchInput").value.toLowerCase().trim();
    const listElem = document.getElementById("filesList");
    if (!listElem) return;

    listElem.innerHTML = "";

    // Folder rows only make sense while browsing, not while searching - a search should span
    // every file regardless of which folder it's in, not just the current level.
    if (!searchVal) {
        childFoldersAt(activeFolderPath).forEach((name) => listElem.appendChild(renderFolderRow(name)));
    }

    const filtered = allFiles.filter(file => {
        if (!file) return false;

        // Filter by Category
        if (activeCategory !== "All" && file.category !== activeCategory) {
            return false;
        }

        // Filter by Search Query (spans all folders when active - see comment above)
        if (searchVal) {
            const nameMatch = file.fileName.toLowerCase().includes(searchVal);
            const tagMatch = file.tags && file.tags.toLowerCase().includes(searchVal);
            return nameMatch || tagMatch;
        }

        // Otherwise, only files that live directly at the current folder level
        return fileMatchesFolderPath(file);
    });

    if (filtered.length === 0) {
        if (listElem.children.length === 0) {
            listElem.innerHTML = '<div class="no-files">No files match your search criteria.</div>';
        }
        return;
    }

    filtered.forEach(file => {
        const item = document.createElement("div");
        item.className = "file-item";

        const info = document.createElement("div");
        info.className = "file-info";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.className = "file-select-checkbox";
        checkbox.checked = selectedFileIds.has(file.fileid);
        checkbox.onclick = (e) => e.stopPropagation();
        checkbox.onchange = () => {
            if (checkbox.checked) selectedFileIds.add(file.fileid);
            else selectedFileIds.delete(file.fileid);
            updateBatchToolbar();
        };
        info.appendChild(checkbox);

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

        // Swapped in once decrypted (icon shows immediately, thumbnail pops in after) - never
        // blocks the initial render. No-op if this row got re-rendered before it resolved.
        if (file.thumbnail) {
            getThumbnailUrl(file).then((url) => {
                if (!url || !icon.isConnected) return;
                const img = document.createElement("img");
                img.className = "file-thumbnail";
                img.src = url;
                img.alt = "";
                icon.replaceWith(img);
            });
        }

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

        // Version History Button
        const historyBtn = document.createElement("button");
        historyBtn.className = "file-action-btn";
        historyBtn.innerHTML = '<i class="ph ph-clock-counter-clockwise"></i>';
        historyBtn.title = file.version > 1 ? `Version History (v${file.version})` : "Version History";
        historyBtn.onclick = () => openVersionHistory(file);

        // Delete Button
        const deleteBtn = document.createElement("button");
        deleteBtn.className = "file-action-btn file-action-danger";
        deleteBtn.innerHTML = '<i class="ph ph-trash"></i>';
        deleteBtn.title = "Delete File";
        deleteBtn.onclick = () => deleteFile(file.fileid, file.fileName);

        actions.appendChild(previewBtn);
        actions.appendChild(downloadBtn);
        actions.appendChild(historyBtn);
        actions.appendChild(deleteBtn);

        item.appendChild(info);
        item.appendChild(actions);
        listElem.appendChild(item);
    });

    updateBatchToolbar();
};

// ============================== BATCH SELECTION ============================ //
const updateBatchToolbar = () => {
    // Drop selections for files no longer in the current list (deleted, or filtered out by
    // a version being superseded) so a stale fileid can't get acted on.
    const liveIds = new Set(allFiles.map((f) => f && f.fileid));
    Array.from(selectedFileIds).forEach((id) => { if (!liveIds.has(id)) selectedFileIds.delete(id); });

    const toolbar = document.getElementById("batchToolbar");
    if (!toolbar) return;
    const count = selectedFileIds.size;
    toolbar.classList.toggle("hide", count === 0);
    const countLabel = document.getElementById("batchSelectedCount");
    if (countLabel) countLabel.textContent = `${count} selected`;
};

const clearSelection = () => {
    selectedFileIds.clear();
    filterFiles();
};

const deleteSelectedFiles = async () => {
    const ids = Array.from(selectedFileIds);
    if (!ids.length) return;
    if (!confirm(`Permanently delete ${ids.length} selected file(s)? This cannot be undone.`)) return;
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    window._suppressDeleteNotify = true;
    let failures = 0;
    for (const fileid of ids) {
        try {
            await sendCorrelated("deleteFile", { fileid });
        } catch (e) {
            console.error(e);
            failures++;
        }
    }
    window._suppressDeleteNotify = false;
    toggleServerBusy(false);
    clearSelection();
    notifyUser({
        head: "Batch Delete Complete",
        body: failures
            ? `${ids.length - failures} of ${ids.length} file(s) deleted (${failures} failed).`
            : `${ids.length} file(s) deleted.`
    });
};

// Fetches, decrypts and bundles the selected files into one ZIP for a single download -
// nothing is ever written to disk unencrypted except inside that final archive.
const downloadSelectedAsZip = async () => {
    const ids = Array.from(selectedFileIds);
    if (!ids.length) return;
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    const zipEntries = [];
    const usedNames = new Set();
    let failures = 0;

    for (const fileid of ids) {
        try {
            const { fileName, decryptedBuffer } = await fetchAndDecryptFile(fileid);

            let name = fileName || "file";
            if (usedNames.has(name)) {
                const dot = name.lastIndexOf(".");
                const base = dot > 0 ? name.slice(0, dot) : name;
                const ext = dot > 0 ? name.slice(dot) : "";
                let n = 2;
                while (usedNames.has(`${base} (${n})${ext}`)) n++;
                name = `${base} (${n})${ext}`;
            }
            usedNames.add(name);

            zipEntries.push({ name, data: new Uint8Array(decryptedBuffer) });
        } catch (e) {
            console.error(e);
            failures++;
        }
    }

    if (!zipEntries.length) {
        toggleServerBusy(false);
        notifyUser({ head: "Download Error", body: "Could not prepare any of the selected files." });
        return;
    }

    const zipBytes = createZip(zipEntries);
    const blob = new Blob([zipBytes], { type: "application/zip" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `blackbox-export-${new Date().toISOString().slice(0, 10)}.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toggleServerBusy(false);
    clearSelection();
    notifyUser({
        head: "ZIP Ready",
        body: failures
            ? `${zipEntries.length} of ${ids.length} file(s) included (${failures} failed).`
            : `${zipEntries.length} file(s) downloaded as ZIP.`
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
// so a single file never has to fit in one websocket/JSON message. Pass docId to upload
// this as a new revision of an existing document instead of a brand new one (see
// promptNewVersion) - the server rejects it if docId doesn't already belong to this user.
const uploadOneFile = async (file, category, userTags, index, total, docId = "") => {
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

    // Thumbnail, if any, is encrypted with the SAME per-file key - nothing new to manage,
    // and anyone who could decrypt the thumbnail could already decrypt the full file anyway.
    let thumbnail = "";
    let thumbnailIv = "";
    const thumbBuffer = await generateThumbnail(file);
    if (thumbBuffer) {
        const wrappedThumb = await encryptData(thumbBuffer, fkKey);
        thumbnail = await bufferToBase64(wrappedThumb.encryptedData);
        thumbnailIv = wrappedThumb.iv;
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
        fileKeyIv: fileKeyIv,
        thumbnail: thumbnail,
        thumbnailIv: thumbnailIv,
        docId: docId
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

// ============================== ZIP WRITER ============================ //
// Minimal ZIP archive writer (STORE method, no compression) for bundling a batch download
// into one file. No new dependency for this - the app has no build step, and this is well
// within a page of well-specified format code. Verified byte-for-byte round-trip (including
// binary content and multi-file offset/CRC correctness) against the real `unzip` before
// this went anywhere near the app.
const crc32Table = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        table[n] = c >>> 0;
    }
    return table;
})();

const crc32 = (bytes) => {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
        crc = crc32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
};

const dosDateTime = (date) => {
    const dosTime = ((date.getHours() & 0x1F) << 11) | ((date.getMinutes() & 0x3F) << 5) | ((date.getSeconds() >> 1) & 0x1F);
    const dosDate = (((date.getFullYear() - 1980) & 0x7F) << 9) | (((date.getMonth() + 1) & 0xF) << 5) | (date.getDate() & 0x1F);
    return { dosTime, dosDate };
};

// files: [{ name, data: Uint8Array }] -> Uint8Array of a complete .zip file
const createZip = (files) => {
    const encoder = new TextEncoder();
    const localParts = [];
    const centralParts = [];
    let offset = 0;
    const { dosTime, dosDate } = dosDateTime(new Date());

    for (const file of files) {
        const nameBytes = encoder.encode(file.name);
        const crc = crc32(file.data);
        const size = file.data.length;

        const localHeader = new DataView(new ArrayBuffer(30));
        localHeader.setUint32(0, 0x04034b50, true); // local file header signature
        localHeader.setUint16(4, 20, true); // version needed to extract
        localHeader.setUint16(6, 0, true); // general purpose flags
        localHeader.setUint16(8, 0, true); // compression method: 0 = store
        localHeader.setUint16(10, dosTime, true);
        localHeader.setUint16(12, dosDate, true);
        localHeader.setUint32(14, crc, true);
        localHeader.setUint32(18, size, true); // compressed size
        localHeader.setUint32(22, size, true); // uncompressed size
        localHeader.setUint16(26, nameBytes.length, true);
        localHeader.setUint16(28, 0, true); // extra field length
        localParts.push(new Uint8Array(localHeader.buffer), nameBytes, file.data);

        const centralHeader = new DataView(new ArrayBuffer(46));
        centralHeader.setUint32(0, 0x02014b50, true); // central directory header signature
        centralHeader.setUint16(4, 20, true); // version made by
        centralHeader.setUint16(6, 20, true); // version needed to extract
        centralHeader.setUint16(8, 0, true);
        centralHeader.setUint16(10, 0, true);
        centralHeader.setUint16(12, dosTime, true);
        centralHeader.setUint16(14, dosDate, true);
        centralHeader.setUint32(16, crc, true);
        centralHeader.setUint32(20, size, true);
        centralHeader.setUint32(24, size, true);
        centralHeader.setUint16(28, nameBytes.length, true);
        centralHeader.setUint16(30, 0, true); // extra field length
        centralHeader.setUint16(32, 0, true); // comment length
        centralHeader.setUint16(34, 0, true); // disk number start
        centralHeader.setUint16(36, 0, true); // internal file attributes
        centralHeader.setUint32(38, 0, true); // external file attributes
        centralHeader.setUint32(42, offset, true); // offset of local header
        centralParts.push(new Uint8Array(centralHeader.buffer), nameBytes);

        offset += 30 + nameBytes.length + size;
    }

    const centralDirOffset = offset;
    const centralDirSize = centralParts.reduce((sum, p) => sum + p.length, 0);

    const eocd = new DataView(new ArrayBuffer(22));
    eocd.setUint32(0, 0x06054b50, true); // end of central directory signature
    eocd.setUint16(4, 0, true);
    eocd.setUint16(6, 0, true);
    eocd.setUint16(8, files.length, true);
    eocd.setUint16(10, files.length, true);
    eocd.setUint32(12, centralDirSize, true);
    eocd.setUint32(16, centralDirOffset, true);
    eocd.setUint16(20, 0, true); // comment length

    const allParts = [...localParts, ...centralParts, new Uint8Array(eocd.buffer)];
    const result = new Uint8Array(allParts.reduce((sum, p) => sum + p.length, 0));
    let pos = 0;
    for (const part of allParts) { result.set(part, pos); pos += part.length; }
    return result;
};

// ============================== DOWNLOAD & PREVIEW HANDLERS ================================= //
// Fetches ciphertext over a plain HTTP GET (bypassing the JSON/websocket round trip) using a
// short-lived, single-use token minted by the server, then decrypts it client-side. Shared by
// single-file download/preview and batch ZIP export (downloadSelectedAsZip below).
const fetchAndDecryptFile = async (fileid) => {
    if (!window.sessionPassword) throw new Error("Not authenticated. Cannot decrypt.");

    const tokenResp = await sendCorrelated("getDownloadToken", { fileid });
    const url = `/download?fileid=${encodeURIComponent(tokenResp.fileid)}&token=${encodeURIComponent(tokenResp.token)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const base64Data = await res.text();

    const fileKey = tokenResp.fileKeyWrapped
        ? await unwrapFileKey(tokenResp.fileKeyWrapped, tokenResp.fileKeyIv)
        : await deriveKeyForSalt(tokenResp.salt);
    const encryptedBuffer = await base64ToBuffer(base64Data);
    const decryptedBuffer = await decryptData(encryptedBuffer, fileKey, tokenResp.iv);

    return { fileName: tokenResp.fileName, mimeType: tokenResp.mimeType, decryptedBuffer };
};

const downloadFile = async (fileid) => {
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    toggleServerBusy(true);
    try {
        const { fileName, mimeType, decryptedBuffer } = await fetchAndDecryptFile(fileid);

        if (currentAction === "download") {
            const blob = new Blob([decryptedBuffer], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            notifyUser({ head: "Download Success", body: `${fileName} downloaded successfully.` });
        } else if (currentAction === "preview") {
            showPreview(fileName, mimeType, decryptedBuffer);
        }
    } catch (e) {
        console.error("Decryption error:", e);
        notifyUser({ head: "Download Error", body: e.message || "Failed to decrypt file payload. Authentication issue?" });
    } finally {
        toggleServerBusy(false);
    }
};

const deleteFile = (fileid, fileName) => {
    if (!confirm(`Permanently delete "${fileName}"? This cannot be undone.`)) return;
    toggleServerBusy(true);
    socket.sendCmd("deleteFile", { fileid: fileid });
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

// ============================== VERSION HISTORY ============================ //
// Set by openVersionHistory, read by promptNewVersion/handleNewVersionFileSelected - carries
// which document a new-version upload (from the hidden file input) should attach to.
let versionHistoryContext = null;

const openVersionHistory = async (file) => {
    versionHistoryContext = { docId: file.docId, category: file.category, tags: file.tags };
    document.getElementById("versionHistoryModal").classList.remove("hide");
    document.getElementById("versionHistoryTitle").textContent = `Version History: ${file.fileName}`;

    const body = document.getElementById("versionHistoryBody");
    body.innerHTML = "";
    const loading = document.createElement("p");
    loading.textContent = "Loading...";
    body.appendChild(loading);

    try {
        const resp = await sendCorrelated("getFileVersions", { docId: file.docId });
        const versions = Array.isArray(resp) ? resp : (resp ? [resp] : []);
        body.innerHTML = "";

        if (!versions.length) {
            const notice = document.createElement("p");
            notice.textContent = "No version history available.";
            body.appendChild(notice);
            return;
        }

        versions.sort((a, b) => b.version - a.version).forEach((v) => {
            const row = document.createElement("div");
            row.className = "file-item";

            const info = document.createElement("div");
            info.className = "file-info";
            const label = document.createElement("span");
            label.className = "file-name";
            const when = v.uploadDate ? new Date(v.uploadDate).toLocaleString() : "";
            label.textContent = `v${v.version}${v.latest ? " (current)" : ""} - ${formatBytes(v.fileSize)} - ${when}`;
            info.appendChild(label);
            row.appendChild(info);

            const actions = document.createElement("div");
            actions.className = "file-actions";
            const dlBtn = document.createElement("button");
            dlBtn.className = "file-action-btn";
            dlBtn.innerHTML = '<i class="ph ph-download-simple"></i>';
            dlBtn.title = "Download this version";
            dlBtn.onclick = () => {
                currentAction = "download";
                downloadFile(v.fileid);
            };
            actions.appendChild(dlBtn);
            row.appendChild(actions);

            body.appendChild(row);
        });
    } catch (e) {
        console.error(e);
        body.innerHTML = "";
        const notice = document.createElement("p");
        notice.textContent = "Failed to load version history.";
        body.appendChild(notice);
    }
};

const closeVersionHistory = () => {
    document.getElementById("versionHistoryModal").classList.add("hide");
    document.getElementById("versionHistoryBody").innerHTML = "";
    versionHistoryContext = null;
};

const promptNewVersion = () => {
    if (!versionHistoryContext) return;
    document.getElementById("newVersionFileInput").click();
};

const handleNewVersionFileSelected = async () => {
    const input = document.getElementById("newVersionFileInput");
    const file = input.files && input.files[0];
    input.value = "";
    if (!file || !versionHistoryContext) return;

    if (!window.sessionPassword || !window.sessionMEK) {
        notifyUser({ head: "Encryption Error", body: "Not authenticated. Cannot encrypt file." });
        return;
    }
    if (pendingResponse) {
        notifyUser({ head: "Please wait", body: "Another operation is already in progress." });
        return;
    }

    // Same category/tags as the version being replaced - this is the same logical document.
    const { docId, category, tags } = versionHistoryContext;
    const userTags = tags ? tags.split(",").map((t) => t.trim()).filter((t) => t) : [];
    closeVersionHistory();

    showUploadProgress(true);
    try {
        // The "uploadSuccess" response (see connect.js) already notifies and refreshes the
        // file list/stats - no need to duplicate that here.
        await uploadOneFile(file, category, userTags, 0, 1, docId);
    } catch (e) {
        console.error(e);
        notifyUser({ head: "Upload Error", body: `Failed to upload new version: ${e.message}` });
    } finally {
        showUploadProgress(false);
    }
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
