/**
 * validate.ts – upload validation: allowlist + magic bytes must match (Rule 8).
 */
const MAX_BYTES = 5 * 1024 * 1024; // 5 MB

interface Kind { mime: string; check: (b: Buffer) => boolean }

const startsWith = (b: Buffer, sig: number[]) => sig.every((v, i) => b[i] === v);

// Text files: reject NUL bytes or markup/script starts.
const isPlainText = (b: Buffer): boolean => {
    const head = b.subarray(0, 4096);
    if (head.includes(0)) return false;
    const s = head.toString('utf8').trimStart().toLowerCase();
    return !(s.startsWith('<') || s.startsWith('#!'));
};

const KINDS: Record<string, Kind> = {
    pdf: { mime: 'application/pdf', check: b => startsWith(b, [0x25, 0x50, 0x44, 0x46]) },
    png: { mime: 'image/png', check: b => startsWith(b, [0x89, 0x50, 0x4e, 0x47]) },
    jpg: { mime: 'image/jpeg', check: b => startsWith(b, [0xff, 0xd8, 0xff]) },
    docx: {
        mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        check: b => startsWith(b, [0x50, 0x4b, 0x03, 0x04])
    },
    xlsx: {
        mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        check: b => startsWith(b, [0x50, 0x4b, 0x03, 0x04])
    },
    txt: { mime: 'text/plain', check: isPlainText },
    csv: { mime: 'text/csv', check: isPlainText },
};

export interface Validated { ok: true; mime: string; displayName: string }
export interface Rejected { ok: false; error: string }

/** Remove path parts, control chars and odd characters from the display name. */
export function sanitiseName(original: string): string {
    const base = original.replace(/\\/g, '/').split('/').pop() ?? '';
    const clean = base.replace(/[^\w.\- ()]/g, '_').replace(/\.{2,}/g, '.').slice(0, 120).trim();
    return clean || 'document';
}

export function validateUpload(originalName: string, data: Buffer): Validated | Rejected {
    if (data.length === 0) return { ok: false, error: 'empty file' };
    if (data.length > MAX_BYTES) return { ok: false, error: 'file too large (max 5 MB)' };

    const displayName = sanitiseName(originalName);
    const parts = displayName.toLowerCase().split('.');
    if (parts.length < 2) return { ok: false, error: 'file type not allowed' };

    // Double-extension defence: every extension after the first must be safe.
    const BAD = ['php', 'js', 'html', 'htm', 'svg', 'exe', 'sh', 'bat', 'cmd', 'com', 'jar', 'dll', 'msi', 'ps1', 'xml'];
    if (parts.slice(1).some(p => BAD.includes(p))) return { ok: false, error: 'file type not allowed' };

    const ext = parts[parts.length - 1]!;
    const kind = KINDS[ext];
    if (!kind) return { ok: false, error: 'file type not allowed' };
    if (!kind.check(data)) return { ok: false, error: 'file content does not match its extension' };

    return { ok: true, mime: kind.mime, displayName };
}