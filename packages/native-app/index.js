#!/usr/bin/env node

const fs = require('fs');

process.on('uncaughtException', (err) => {
    fs.writeFileSync('/tmp/native-error.log', `Uncaught Exception: ${err.stack}`);
    process.exit(1);
});

process.stdin.on('readable', () => {
    try {
        const input = process.stdin;

        const rawLen = input.read(4);
        if (!rawLen) return;

        const msgLen = rawLen.readUInt32LE(0);
        const rawMsg = input.read(msgLen);
        if (!rawMsg) return;

        const message = JSON.parse(rawMsg.toString());
        fs.writeFileSync('/tmp/native-received.log', `Received: ${JSON.stringify(message)}`);

        sendMessage({ text: "pong from native app" });
    } catch (e) {
        fs.writeFileSync('/tmp/native-error.log', `Caught Exception: ${e.stack}`);
        process.exit(1);
    }
});

function sendMessage(msg) {
    const json = JSON.stringify(msg);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(Buffer.byteLength(json), 0);
    process.stdout.write(lenBuf);
    process.stdout.write(json);
}
