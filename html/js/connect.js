const connect = () => {
    const socket = {
        ws: null,
        sendCmd: null
    };

    let reconnectTimeout = null;

    const establishConnection = () => {
        // The q process serves this page and the websocket on the same host:port,
        // so derive the socket URL from the page location (falls back for file://).
        const wsUrl = `ws://${window.location.host || "localhost:50667"}`;

        console.log(`Connecting to ${wsUrl}...`);
        const ws = new WebSocket(wsUrl);
        ws.binaryType = "arraybuffer";
        socket.ws = ws;

        ws.onopen = () => {
            console.log("WebSocket connected.");
            const msg = { head: "Welcome to BlackBox", body: "Successfully connected to blackbox!" };
            notifyUser(msg);
            authUser(); // Triggers the modal instead of prompt
            if (reconnectTimeout) {
                clearTimeout(reconnectTimeout);
                reconnectTimeout = null;
            }
        };

        ws.onclose = (event) => {
            console.warn("Connection to the server has closed", event);
            notifyUser({ head: "Connection Lost", body: "Disconnected from the server. Reconnecting in 3s..." });
            // Show overlay since connection is lost
            toggleServerBusy(true);

            // Reconnect
            if (!reconnectTimeout) {
                reconnectTimeout = setTimeout(establishConnection, 3000);
            }
        };

        ws.onerror = (err) => {
            console.error("WebSocket Error:", err);
            ws.close();
        };

        ws.onmessage = (msg) => {
            if (typeof deserialize !== 'function') {
                console.error("c.js deserialize function is missing!");
                return;
            }

            try {
                const raw = JSON.parse(deserialize(msg.data));
                const msgType = raw[0];
                const msgData = raw[1];

                switch (msgType) {
                    case "authResp":
                        toggleServerBusy(false);
                        handleAuth(msgData);
                        break;
                    case "numUsers":
                        updUsersOnline(msgData);
                        break;
                    case "fileListUpdated":
                        // Pushed when a file changed from another tab/device for this same
                        // user - just re-fetch, no diff is sent.
                        if (window.currentUser) {
                            socket.sendCmd("recentUploadsForUser", { userid: window.currentUser });
                            socket.sendCmd("getSystemStats", { userid: window.currentUser });
                        }
                        break;
                    case "notifyUser":
                        toggleServerBusy(false);
                        notifyUser(msgData);
                        break;
                    case "recentUploads":
                        toggleServerBusy(false);
                        updateRecentUploads(msgData);
                        break;
                    case "uploadStarted":
                    case "chunkAck":
                    case "downloadToken":
                    case "mekSet":
                    case "passwordChanged":
                    case "authChallenge":
                    case "legacyAuthUpgraded":
                    case "fileVersions":
                    case "adminUsersList":
                    case "adminUserCreated":
                    case "adminUserDeleted":
                        if (pendingResponse) {
                            const { resolve } = pendingResponse;
                            pendingResponse = null;
                            resolve(msgData);
                        }
                        break;
                    case "uploadSuccess":
                        if (pendingResponse) {
                            const { resolve } = pendingResponse;
                            pendingResponse = null;
                            resolve(msgData);
                        }
                        notifyUser({ head: "Upload Success", body: `File ${msgData} uploaded successfully.` });
                        // Refresh files list and stats
                        if (typeof window.currentUser !== 'undefined') {
                            socket.sendCmd("recentUploadsForUser", { userid: window.currentUser });
                            socket.sendCmd("getSystemStats", { userid: window.currentUser });
                        }
                        break;
                    case "deleteSuccess":
                        toggleServerBusy(false);
                        // Batch delete (deleteSelectedFiles) awaits each call via sendCorrelated
                        // and shows its own single summary toast instead of one per file.
                        if (pendingResponse) {
                            const { resolve } = pendingResponse;
                            pendingResponse = null;
                            resolve(msgData);
                        }
                        if (!window._suppressDeleteNotify) {
                            notifyUser({ head: "File Deleted", body: "File removed from the vault." });
                        }
                        if (window.currentUser) {
                            socket.sendCmd("recentUploadsForUser", { userid: window.currentUser });
                            socket.sendCmd("getSystemStats", { userid: window.currentUser });
                        }
                        break;
                    case "systemStats":
                        toggleServerBusy(false);
                        updateSystemStats(msgData);
                        break;
                    case "Error":
                        toggleServerBusy(false);
                        if (pendingResponse) {
                            const { reject } = pendingResponse;
                            pendingResponse = null;
                            reject(new Error(msgData));
                        } else {
                            notifyUser({ head: "Server Error", body: msgData });
                        }
                        break;
                    default:
                        toggleServerBusy(false);
                        console.log("No handler for message type: ", msgType);
                }
            } catch (e) {
                console.error("Failed to parse message from server", e);
            }
        };
    };

    // Send command to q server helper function
    socket.sendCmd = (qFunc, qParams) => {
        if (!socket.ws || socket.ws.readyState !== WebSocket.OPEN) {
            console.warn("WebSocket is not open. Cannot send command:", qFunc);
            notifyUser({ head: "Error", body: "Not connected to the server." });
            return;
        }
        window.prevFunc = qFunc;
        window.prevParams = qParams;
        const requestObj = { func: qFunc, params: qParams };

        if (typeof serialize === 'function') {
            socket.ws.send(serialize(JSON.stringify(requestObj)));
        } else {
            console.error("c.js serialize function is missing!");
        }
    };

    establishConnection();
    return socket;
};
