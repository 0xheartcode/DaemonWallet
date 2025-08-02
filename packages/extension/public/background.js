chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "pingNative") {
        const port = chrome.runtime.connectNative('com.example.helloworld');

        port.onMessage.addListener((response) => {
            console.log("Received from native app:", response);
            sendResponse(response);
        });

        port.onDisconnect.addListener(() => {
            console.error("Native app disconnected");
            if (chrome.runtime.lastError) {
                console.error("Runtime error:", chrome.runtime.lastError.message);
            }
        });

        port.postMessage({ text: "Hello from extension!" });

        // Return true to allow async sendResponse
        return true;
    }
});
