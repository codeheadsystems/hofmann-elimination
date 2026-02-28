/**
 * Hofmann OPAQUE demo — browser entry point.
 * Imported by demo.html via <script type="module">.
 */
import { OpaqueHttpClient } from './src/opaque/http.js';
import { OprfHttpClient } from './src/oprf/http.js';
import { argon2idKsf, identityKsf, type KSF } from './src/opaque/ksf.js';
import { toHex } from './src/crypto/primitives.js';
import { strToBytes } from './src/crypto/encoding.js';

// ── DOM helpers ──────────────────────────────────────────────────────────────

function $<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function val(id: string): string {
  return ($<HTMLInputElement>(id)).value.trim();
}

function setStatus(
  id: string,
  state: 'idle' | 'running' | 'ok' | 'err',
  text: string
) {
  const el = $(id);
  el.className = `status-chip ${state}`;
  const pulseClass = state === 'running' ? 'dot pulse' : 'dot';
  el.innerHTML = `<span class="${pulseClass}"></span> ${text}`;
}

function showResult(boxId: string, textId: string, text: string, isErr = false) {
  const box = $(boxId);
  const txt = $(textId);
  box.classList.add('visible');
  txt.className = isErr ? 'result-value err' : 'result-value';
  txt.textContent = text;
}

// ── Activity log ─────────────────────────────────────────────────────────────

type LogLevel = 'info' | 'ok' | 'err' | 'step' | 'data';

function log(msg: string, level: LogLevel = 'info') {
  const logEl = $('log');
  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}.${String(now.getMilliseconds()).padStart(3,'0')}`;
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="log-ts">${ts}</span><span class="log-msg log-${level}">${escHtml(msg)}</span>`;
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Config readers ────────────────────────────────────────────────────────────

function getServerUrl(): string {
  return val('serverUrl') || 'http://localhost:8080';
}

function getKSF(): KSF {
  const mem = parseInt(val('argon2Memory'), 10);
  if (!mem) return identityKsf;
  const iter  = parseInt(val('argon2Iterations'), 10) || 3;
  const par   = parseInt(val('argon2Parallelism'), 10) || 1;
  return argon2idKsf(mem, iter, par);
}

function getOpaqueClient(): OpaqueHttpClient {
  const ctx = val('context');
  const ksf = getKSF();
  const mem = parseInt(val('argon2Memory'), 10);
  log(`Context: "${ctx}" | KSF: ${mem ? `Argon2id(${mem}KiB, iter=${val('argon2Iterations')})` : 'identity'}`, 'data');
  return new OpaqueHttpClient(getServerUrl(), { context: ctx, ksf });
}

// ── OPAQUE Registration ───────────────────────────────────────────────────────

$('btnRegister').addEventListener('click', async () => {
  const credId   = val('regCredId');
  const password = val('regPassword');
  if (!credId || !password) { log('Credential ID and password are required', 'err'); return; }

  setStatus('regStatus', 'running', 'Registering…');
  log(`── Registration: ${credId}`, 'step');
  const t0 = Date.now();

  try {
    const client = getOpaqueClient();
    log('Sending KE1 (registration start)…', 'info');
    await client.register(credId, password);
    const elapsed = Date.now() - t0;
    setStatus('regStatus', 'ok', `Done (${elapsed}ms)`);
    showResult('regResult', 'regResultText', `Registration successful in ${elapsed}ms`);
    log(`Registration complete for "${credId}" (${elapsed}ms)`, 'ok');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('regStatus', 'err', 'Failed');
    showResult('regResult', 'regResultText', msg, true);
    log(`Registration failed: ${msg}`, 'err');
  }
});

// ── OPAQUE Authentication ─────────────────────────────────────────────────────

$('btnAuth').addEventListener('click', async () => {
  const credId   = val('authCredId');
  const password = val('authPassword');
  if (!credId || !password) { log('Credential ID and password are required', 'err'); return; }

  setStatus('authStatus', 'running', 'Authenticating…');
  log(`── Authentication: ${credId}`, 'step');
  const t0 = Date.now();

  try {
    const client = getOpaqueClient();
    log('Generating KE1 (blinding password)…', 'info');
    const token = await client.authenticate(credId, password);
    const elapsed = Date.now() - t0;
    setStatus('authStatus', 'ok', `Done (${elapsed}ms)`);
    $<HTMLInputElement>('authToken').value = token;
    $('authResult').classList.add('visible');
    // Auto-fill whoami and delete token fields
    $<HTMLInputElement>('whoamiToken').value = token;
    $<HTMLInputElement>('delToken').value = token;
    $<HTMLInputElement>('delCredId').value = credId;
    log(`Authentication successful for "${credId}" (${elapsed}ms)`, 'ok');
    log(`JWT: ${token.substring(0, 40)}…`, 'data');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('authStatus', 'err', 'Failed');
    log(`Authentication failed: ${msg}`, 'err');
  }
});

$('btnCopyToken').addEventListener('click', () => {
  const token = $<HTMLInputElement>('authToken').value;
  if (!token) return;
  navigator.clipboard.writeText(token).then(() => log('JWT token copied to clipboard', 'ok'));
});

// ── Whoami ────────────────────────────────────────────────────────────────────

$('btnWhoami').addEventListener('click', async () => {
  const token = val('whoamiToken');
  if (!token) { log('JWT token is required', 'err'); return; }

  setStatus('whoamiStatus', 'running', 'Calling…');
  log('── GET /api/whoami', 'step');
  const t0 = Date.now();

  try {
    const url = `${getServerUrl()}/api/whoami`;
    const response = await fetch(url, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const elapsed = Date.now() - t0;
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText} — ${text}`);
    }
    setStatus('whoamiStatus', 'ok', `${response.status} OK (${elapsed}ms)`);
    showResult('whoamiResult', 'whoamiResultText', text);
    log(`Whoami (${elapsed}ms): ${text}`, 'ok');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('whoamiStatus', 'err', 'Failed');
    showResult('whoamiResult', 'whoamiResultText', msg, true);
    log(`Whoami failed: ${msg}`, 'err');
  }
});

// ── OPAQUE Delete ─────────────────────────────────────────────────────────────

$('btnDelete').addEventListener('click', async () => {
  const credId = val('delCredId');
  const token  = val('delToken');
  if (!credId || !token) { log('Credential ID and JWT token are required', 'err'); return; }

  setStatus('delStatus', 'running', 'Deleting…');
  log(`── Delete registration: ${credId}`, 'step');
  const t0 = Date.now();

  try {
    const client = getOpaqueClient();
    await client.deleteRegistration(credId, token);
    const elapsed = Date.now() - t0;
    setStatus('delStatus', 'ok', `Done (${elapsed}ms)`);
    showResult('delResult', 'delResultText', `Registration for "${credId}" deleted`);
    log(`Deleted registration for "${credId}" (${elapsed}ms)`, 'ok');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('delStatus', 'err', 'Failed');
    showResult('delResult', 'delResultText', msg, true);
    log(`Delete failed: ${msg}`, 'err');
  }
});

// ── Standalone OPRF ───────────────────────────────────────────────────────────

$('btnOprf').addEventListener('click', async () => {
  const input = val('oprfInput');
  if (!input) { log('OPRF input is required', 'err'); return; }

  setStatus('oprfStatus', 'running', 'Evaluating…');
  log(`── OPRF evaluate: "${input}"`, 'step');
  const t0 = Date.now();

  try {
    const client = new OprfHttpClient(getServerUrl());
    const result = await client.evaluate(strToBytes(input));
    const elapsed = Date.now() - t0;
    const hex = toHex(result);
    setStatus('oprfStatus', 'ok', `Done (${elapsed}ms)`);
    showResult('oprfResult', 'oprfResultText', hex);
    log(`OPRF output: ${hex.substring(0, 20)}… (${elapsed}ms)`, 'ok');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('oprfStatus', 'err', 'Failed');
    log(`OPRF failed: ${msg}`, 'err');
  }
});

// ── Log clear ────────────────────────────────────────────────────────────────

$('btnClearLog').addEventListener('click', () => {
  $('log').innerHTML = '';
});

// ── Initial greeting ──────────────────────────────────────────────────────────

log('Hofmann OPAQUE demo loaded', 'ok');
log(`Server: ${getServerUrl()}`, 'data');
