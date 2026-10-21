'use strict';
/* Strongroom UI. No innerHTML anywhere: all text goes through textContent (XSS-safe). */
const app = document.getElementById('app');
const live = document.getElementById('live');
const state = { me: null, users: new Map(), userList: [], tab: 'mine', docs: [] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : '');
const short = (id) => (id ? id.slice(0, 8) : '—');
const who = (id) => (id ? state.users.get(id) || short(id) : '—');
const kb = (n) => (n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB');

function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (k === 'class') e.className = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else if (v === true) e.setAttribute(k, '');
        else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const c of kids.flat()) {
        if (c == null || c === false) continue;
        e.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return e;
}

function say(msg, bad) {
    live.textContent = msg;
    live.className = bad ? 'toast bad' : 'toast';
    live.hidden = false;
    clearTimeout(say.t);
    say.t = setTimeout(() => { live.hidden = true; }, 4500);
}

async function api(path, opts) {
    const { method = 'GET', body, form } = opts || {};
    const o = { method, credentials: 'same-origin', headers: { 'X-Requested-With': 'strongroom' } };
    if (form) o.body = form;
    else if (body) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(body); }
    const r = await fetch(path, o);
    let data = null;
    try { data = await r.json(); } catch (e) { /* no body */ }
    if (!r.ok) {
        if (r.status === 401 && state.me) { state.me = null; showLogin(); }
        const err = new Error((data && data.error) || 'error ' + r.status);
        err.status = r.status;
        throw err;
    }
    return data;
}

/* ---------- login ---------- */
const DEMO = [
    ['Admin', 'admin@strongroom.local', 'Admin$ecret1!'],
    ['Owner 1', 'owner1@strongroom.local', 'Owner$ecret1!'],
    ['Owner 2', 'owner2@strongroom.local', 'Owner$ecret2!'],
    ['Viewer 1', 'viewer1@strongroom.local', 'Viewer$ecret1!'],
    ['Viewer 2', 'viewer2@strongroom.local', 'Viewer$ecret2!'],
];

function showLogin() {
    const email = h('input', { id: 'email', type: 'email', autocomplete: 'username', required: true });
    const pw = h('input', { id: 'pw', type: 'password', autocomplete: 'current-password', required: true });
    const btn = h('button', { class: 'primary', type: 'submit' }, 'Unlock');
    const form = h('form', {
        onsubmit: async (ev) => {
            ev.preventDefault();
            btn.disabled = true;
            try {
                await api('/api/auth/login', { method: 'POST', body: { email: email.value, password: pw.value } });
                await boot();
            } catch (e) { say('Invalid credentials', true); }
            btn.disabled = false;
        },
    },
        h('label', { for: 'email' }, 'Email'), email,
        h('label', { for: 'pw' }, 'Password'), pw,
        h('p', null, btn));
    app.replaceChildren(h('div', { class: 'login' },
        h('h1', null, 'STRONGROOM'),
        h('p', { class: 'muted' }, 'Every door guarded. Every opening logged.'),
        h('div', { class: 'card' }, form,
            h('p', { class: 'tag' }, 'Demo accounts (public demo data only):'),
            h('div', { class: 'demo' }, DEMO.map(([n, e, p]) =>
                h('button', { type: 'button', onclick: () => { email.value = e; pw.value = p; } }, n))))));
}

/* ---------- shell ---------- */
async function boot() {
    try { state.me = await api('/api/auth/me'); } catch (e) { state.me = null; return showLogin(); }
    state.users = new Map(); state.userList = [];
    if (state.me.role !== 'viewer') {
        try {
            const u = await api('/api/users');
            state.userList = u.items;
            state.users = new Map(u.items.map((x) => [x.id, x.name]));
        } catch (e) { /* directory is optional */ }
    }
    state.users.set(state.me.id, state.me.name);
    shell();
}

function shell() {
    const main = h('main', { id: 'main' });
    app.replaceChildren(
        h('header', { class: 'top' },
            h('div', { class: 'brand' }, h('span', { class: 'lock', 'aria-hidden': 'true' }), 'STRONGROOM'),
            h('span', { class: 'spacer' }),
            h('span', null, state.me.name), h('span', { class: 'badge ' + state.me.role }, state.me.role),
            h('button', { onclick: async () => { try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) { } state.me = null; showLogin(); } }, 'Log out')),
        main);
    if (state.me.role === 'admin') adminView(main); else docsView(main);
}

/* ---------- documents ---------- */
function docsView(main) {
    const isOwner = state.me.role === 'owner';
    if (!isOwner) state.tab = 'shared';
    const list = h('div', { class: 'card', 'aria-live': 'polite' });
    const detail = h('div', { class: 'card', id: 'detail', hidden: true });
    const q = h('input', { id: 'q', type: 'search', placeholder: 'name contains…' });
    const cat = h('input', { id: 'cat', placeholder: 'category' });
    const tabs = h('div', { class: 'row' });

    async function load() {
        const p = new URLSearchParams();
        if (q.value) p.set('q', q.value);
        if (cat.value) p.set('category', cat.value);
        try { state.docs = (await api('/api/documents?' + p)).items; } catch (e) { return say('Could not load documents', true); }
        paint();
    }
    function paint() {
        const items = state.docs.filter((d) => (state.tab === 'mine' ? d.access === 'owner' : d.access !== 'owner'));
        tabs.replaceChildren(...(isOwner ? [['mine', 'My documents'], ['shared', 'Shared with me']] : [['shared', 'Shared with me']])
            .map(([k, label]) => h('button', { class: 'tab', 'aria-current': String(state.tab === k), onclick: () => { state.tab = k; paint(); } }, label)));
        list.replaceChildren(
            ...(items.length ? items.map((d) => h('div', { class: 'doc' },
                h('div', null,
                    h('div', { class: 'name' }, d.name),
                    h('div', { class: 'meta' }, [d.category, kb(d.size), 'owner: ' + d.owner_name, fmt(d.created_at)].join(' · '))),
                h('div', { class: 'row' },
                    h('span', { class: 'badge ' + d.access }, d.access),
                    h('button', { onclick: () => download(d) }, 'Download'),
                    d.access === 'owner' ? h('button', { class: 'primary', onclick: () => openDetail(d, detail) }, 'Share & custody') : null)))
                : [h('p', { class: 'muted' }, state.tab === 'mine' ? 'No documents yet.' : 'Nothing has been shared with you.')]));
    }

    const search = h('form', { class: 'row', onsubmit: (e) => { e.preventDefault(); load(); } },
        h('div', null, h('label', { for: 'q' }, 'Search'), q),
        h('div', null, h('label', { for: 'cat' }, 'Category'), cat),
        h('button', { type: 'submit' }, 'Search'));

    main.replaceChildren(h('div', { class: 'grid two' },
        h('div', null, h('div', { class: 'card' }, search), tabs, list, isOwner ? uploadCard(load) : null),
        detail));
    load();
}

async function download(d) {
    try {
        const t = await api('/api/documents/' + d.id + '/download-ticket', { method: 'POST' });
        const r = await fetch('/api/download/' + t.ticket, { credentials: 'same-origin' });
        if (!r.ok) throw new Error('refused');
        const url = URL.createObjectURL(await r.blob());
        const a = h('a', { href: url, download: d.name });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1500);
        say('Downloaded ' + d.name);
    } catch (e) { say('Refused: no access, or access was revoked', true); }
}

function uploadCard(reload) {
    const file = h('input', { type: 'file', id: 'file', accept: '.pdf,.docx,.xlsx,.png,.jpg,.txt,.csv' });
    const cat = h('input', { id: 'upcat', value: 'General', maxlength: '40' });
    const drop = h('div', { class: 'drop', tabindex: '0' }, 'Drop a file here, or choose one below (pdf, docx, xlsx, png, jpg, txt, csv · max 5 MB)');
    let picked = null;
    const setFile = (f) => { picked = f; drop.textContent = f ? 'Selected: ' + f.name : 'Drop a file here'; };
    ['dragenter', 'dragover'].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (e) => setFile(e.dataTransfer.files[0] || null));
    file.addEventListener('change', () => setFile(file.files[0] || null));
    const btn = h('button', { class: 'primary', type: 'submit' }, 'Encrypt & upload');
    return h('form', {
        class: 'card',
        onsubmit: async (e) => {
            e.preventDefault();
            if (!picked) return say('Choose a file first', true);
            const fd = new FormData();
            fd.append('category', cat.value || 'General');
            fd.append('file', picked);
            btn.disabled = true;
            try { const r = await api('/api/documents', { method: 'POST', form: fd }); say('Uploaded ' + r.name); setFile(null); file.value = ''; reload(); }
            catch (err) { say('Upload rejected: ' + err.message, true); }
            btn.disabled = false;
        },
    }, h('h2', null, 'Upload'), drop,
        h('div', { class: 'row' }, h('div', null, h('label', { for: 'file' }, 'File'), file), h('div', null, h('label', { for: 'upcat' }, 'Category'), cat), btn));
}

async function openDetail(d, box) {
    box.hidden = false;
    box.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
    let g, c;
    try {
        [g, c] = await Promise.all([api('/api/documents/' + d.id + '/grants'), api('/api/documents/' + d.id + '/custody')]);
    } catch (e) { box.replaceChildren(h('p', null, 'Not available.')); return; }

    const sel = h('select', { id: 'gu' }, state.userList.map((u) => h('option', { value: u.id }, u.name + ' (' + u.role + ')')));
    const perm = h('select', { id: 'gp' }, h('option', { value: 'read' }, 'read'), h('option', { value: 'edit' }, 'edit'));
    const exp = h('input', { id: 'ge', type: 'datetime-local' });
    const add = h('form', {
        class: 'row',
        onsubmit: async (e) => {
            e.preventDefault();
            const body = { userId: sel.value, permission: perm.value };
            if (exp.value) body.expiresAt = new Date(exp.value).toISOString();
            try { await api('/api/documents/' + d.id + '/grants', { method: 'POST', body }); say('Access granted'); openDetail(d, box); }
            catch (err) { say('Grant failed: ' + err.message, true); }
        },
    },
        h('div', null, h('label', { for: 'gu' }, 'Person'), sel),
        h('div', null, h('label', { for: 'gp' }, 'Permission'), perm),
        h('div', null, h('label', { for: 'ge' }, 'Expires (optional)'), exp),
        h('button', { class: 'primary', type: 'submit' }, 'Grant'));

    box.replaceChildren(
        h('h2', null, d.name),
        h('h3', null, 'Who has access'),
        g.items.length
            ? h('ul', { class: 'plain' }, g.items.map((x) => h('li', null,
                h('span', null, x.name + ' · ', h('span', { class: 'badge ' + x.permission }, x.permission), x.expires_at ? ' · until ' + fmt(x.expires_at) : ''),
                h('button', {
                    class: 'danger', onclick: async () => {
                        try { await api('/api/documents/' + d.id + '/grants/' + x.id, { method: 'DELETE' }); say('Access revoked: effective immediately'); openDetail(d, box); }
                        catch (e) { say('Revoke failed', true); }
                    }
                }, 'Revoke'))))
            : h('p', { class: 'muted' }, 'Only you.'),
        h('h3', null, 'Share'), add,
        h('h3', { style: 'margin-top:1rem' }, 'Chain of custody'),
        h('p', { class: 'tag' }, 'Green = allowed · red = refused. Refusals are recorded too.'),
        h('ul', { class: 'timeline' }, c.items.map((r) => h('li', { class: r.outcome },
            h('span', { class: 't' }, fmt(r.ts) + ' · #' + r.id),
            r.action + ' by ' + who(r.actor_id) + (r.target_user_id ? ' → ' + who(r.target_user_id) : '') + ' · ' + r.outcome))));
}

/* ---------- admin ---------- */
function adminView(main) {
    const notable = h('div', { class: 'card' }, h('h2', null, 'Tripwire panel'), h('p', { class: 'muted' }, 'Loading…'));
    const verifyBox = h('div', { 'aria-live': 'polite' });
    const auditBox = h('div', { class: 'scroll' });
    const action = h('input', { id: 'fa', placeholder: 'e.g. DOWNLOAD' });
    const outcome = h('select', { id: 'fo' }, h('option', { value: '' }, 'any'), h('option', { value: 'DENIED' }, 'DENIED'), h('option', { value: 'ALLOWED' }, 'ALLOWED'));

    async function loadNotable() {
        try {
            const n = await api('/api/admin/notable');
            const sec = (title, rows, line) => h('div', null, h('h3', null, title + ' (' + rows.length + ')'),
                rows.length ? h('ul', { class: 'plain' }, rows.map((r) => h('li', null, line(r)))) : h('p', { class: 'muted' }, 'Nothing flagged.'));
            notable.replaceChildren(h('h2', null, 'Tripwire panel'),
                sec('Repeated denials (5+ in 10 min)', n.repeatedDenials, (r) => who(r.actor_id) + ': ' + r.denials + ' refusals'),
                sec('Attempts by disabled users', n.disabledUserAttempts, (r) => fmt(r.ts) + ' · ' + who(r.actor_id) + ' · ' + r.action),
                sec('Recent permission changes', n.recentGrantsRevokes, (r) => fmt(r.ts) + ' · ' + r.action + ' ' + who(r.actor_id) + ' → ' + who(r.target_user_id)));
        } catch (e) { say('Could not load tripwires', true); }
    }
    async function loadAudit() {
        const p = new URLSearchParams({ limit: '100' });
        if (action.value) p.set('action', action.value.toUpperCase());
        if (outcome.value) p.set('outcome', outcome.value);
        try {
            const a = await api('/api/admin/audit?' + p);
            auditBox.replaceChildren(h('table', null,
                h('thead', null, h('tr', null, ['#', 'Time', 'Actor', 'Action', 'Document', 'Target', 'Outcome', 'IP', 'Hash'].map((x) => h('th', null, x)))),
                h('tbody', null, a.items.map((r) => h('tr', null,
                    h('td', { class: 'mono' }, r.id), h('td', null, fmt(r.ts)), h('td', null, who(r.actor_id)), h('td', null, r.action),
                    h('td', { class: 'mono' }, short(r.document_id)), h('td', null, who(r.target_user_id)),
                    h('td', { class: r.outcome === 'DENIED' ? 'den' : 'alw' }, r.outcome), h('td', { class: 'mono' }, r.ip || ''),
                    h('td', { class: 'mono' }, r.hash.slice(0, 10) + '…'))))));
        } catch (e) { say('Could not load audit log', true); }
    }
    async function verify() {
        verifyBox.replaceChildren(h('p', { class: 'muted' }, 'Recomputing every hash in the chain…'));
        let r;
        try { r = await api('/api/admin/audit/verify'); } catch (e) { return say('Verify failed', true); }
        const n = Math.min(r.rows, 90);
        const strip = h('div', { class: 'chain' });
        const verdict = h('p', { class: 'verdict' });
        verifyBox.replaceChildren(strip, verdict);
        const stop = r.ok ? n : Math.min(n - 1, Math.floor(((r.firstBrokenId - 1) / r.rows) * n));
        for (let i = 0; i < n; i++) {
            const b = h('span', { class: 'blk' }); strip.append(b); await sleep(14);
            if (!r.ok && i === stop) { b.classList.add('bad'); break; }
            b.classList.add('ok');
        }
        verdict.className = 'verdict ' + (r.ok ? 'ok' : 'bad');
        verdict.textContent = r.ok ? '✓ Ledger intact · ' + r.rows + ' entries' : '✗ Chain broken at entry #' + r.firstBrokenId;
        if (r.ok && r.head) verifyBox.append(h('p', { class: 'tag mono' }, 'head: ' + r.head));
    }

    main.replaceChildren(
        h('p', { class: 'muted' }, 'Admins see activity and permission changes, never document contents.'),
        h('div', { class: 'grid two' }, notable,
            h('div', { class: 'card' }, h('h2', null, 'Ledger'), h('button', { class: 'primary', onclick: verify }, 'Verify ledger'), verifyBox)),
        h('div', { class: 'card' }, h('h2', null, 'Audit browser'),
            h('form', { class: 'row', onsubmit: (e) => { e.preventDefault(); loadAudit(); } },
                h('div', null, h('label', { for: 'fa' }, 'Action'), action),
                h('div', null, h('label', { for: 'fo' }, 'Outcome'), outcome),
                h('button', { type: 'submit' }, 'Filter')), auditBox));
    loadNotable(); loadAudit();
}

boot();