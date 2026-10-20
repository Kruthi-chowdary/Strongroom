/**
 * crypto.ts – AES-256-GCM encryption of files at rest (Rule 6).
 * File layout on disk: [12-byte IV][16-byte auth tag][ciphertext].
 * FILE_ENCRYPTION_KEY must be 64 hex chars (32 bytes).
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

function getKey(): Buffer {
    const hex = process.env['FILE_ENCRYPTION_KEY'] ?? '';
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error('FILE_ENCRYPTION_KEY must be 64 hex characters');
    }
    return Buffer.from(hex, 'hex');
}

export function storageDir(): string {
    const dir = process.env['STORAGE_DIR'] ?? path.join(process.cwd(), 'storage');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
}

/** Path is built ONLY from a server-generated UUID, never user input (Rule 6). */
function filePath(storageKey: string): string {
    if (!/^[0-9a-f-]{36}$/.test(storageKey)) throw new Error('bad storage key');
    return path.join(storageDir(), storageKey + '.bin');
}

export function encryptAndStore(storageKey: string, plain: Buffer): void {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
    const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    fs.writeFileSync(filePath(storageKey), Buffer.concat([iv, tag, enc]), { mode: 0o600 });
}

export function readAndDecrypt(storageKey: string): Buffer {
    const raw = fs.readFileSync(filePath(storageKey));
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const enc = raw.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]);
}