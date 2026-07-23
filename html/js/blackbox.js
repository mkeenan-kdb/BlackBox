// Modernized secure digital vault JS
window.currentUser = "";
window.sessionPassword = null; // kept in memory for the session to derive per-file keys
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
const deriveKeyForSalt = async (saltBase64) => {
    const salt = saltBase64 ? new Uint8Array(await base64ToBuffer(saltBase64)) : LEGACY_SALT;
    return deriveKeyFromPassword(window.sessionPassword, salt);
};

// ============================== AUTH FLOW ============================ //
const authUser = () => {
    const modal = document.getElementById("authModal");
    modal.classList.remove("hide");
    document.getElementById("logoutBtn").classList.add("hide");
    document.getElementById("usernameInput").focus();
};

const submitAuth = () => {
    const userinp = document.getElementById("usernameInput").value.trim();
    const userpass = document.getElementById("passwordInput").value;

    if (!userinp || !userpass) {
        notifyUser({ head: "Error", body: "Please enter both username and passphrase." });
        return;
    }

    window.tempPassword = userpass;

    document.querySelector(".modal-body").classList.add("hide");
    document.getElementById("authSpinner").classList.remove("hide");

    socket.sendCmd("authUser", { userid: userinp, pass: userpass });
};

const handleAuth = async (resp) => {
    document.querySelector(".modal-body").classList.remove("hide");
    document.getElementById("authSpinner").classList.add("hide");

    if (resp !== true) {
        notifyUser({ head: "Authentication Failed", body: "Not authorised. Try again." });
        document.getElementById("passwordInput").value = "";
        window.tempPassword = null;
        document.getElementById("usernameInput").focus();
    } else {
        console.log("Authentication successful");
        window.currentUser = document.getElementById("usernameInput").value.trim();

        // Keep the password in memory for the session so each file can use its own salt
        window.sessionPassword = window.tempPassword;
        window.tempPassword = null;

        document.getElementById("authModal").classList.add("hide");
        document.getElementById("logoutBtn").classList.remove("hide");
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
    const fileSalt = crypto.getRandomValues(new Uint8Array(16));
    const fileKey = await deriveKeyFromPassword(window.sessionPassword, fileSalt);
    const { encryptedData, iv } = await encryptData(arrayBuffer, fileKey);
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
        salt: await bufferToBase64(fileSalt.buffer)
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
    if (!window.sessionPassword) {
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
        const fileKey = await deriveKeyForSalt(msgData.salt);
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
