/**
 * crypto.js — Plessen Config Loader
 *
 * The ONLY file in the repo with plessen-auth credentials.
 * No sub-system credentials live here — those are in encrypted config.js.
 *
 * Flow:
 *  1. Initializes minimal plessen-auth Firebase (apiKey + projectId only)
 *  2. On authenticated user → fetches decryption script + key from Firestore
 *  3. Fetches /config.js encrypted blob
 *  4. Decrypts and returns config object
 *  5. Immediately nulls all sensitive intermediates
 */

import { initializeApp, getApps, getApp }
  from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js';
import { getAuth, onAuthStateChanged, signOut as fbSignOut }
  from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js';
import { getFirestore, doc, getDoc, getDocs, collection, addDoc, serverTimestamp, onSnapshot }
  from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js';

// ── Minimal portal bootstrap ──────────────────────────────────────────────────
// Only these two values are exposed in the repo. Everything else is encrypted.
const PORTAL_MIN = {
  apiKey:     "AIzaSyAeboC3xoZR_jyUs1yqBpqK4LgFkBnXEwQ",
  authDomain: "plessen-auth.firebaseapp.com",
  projectId:  "plessen-auth"
};

// ── Singleton portal Firebase instance ───────────────────────────────────────
function _getPortal() {
  const name = "plessen-portal-min";
  const app  = getApps().find(a => a.name === name) || initializeApp(PORTAL_MIN, name);
  return { app, auth: getAuth(app), db: getFirestore(app) };
}

export const { app: portalApp, auth: portalAuth, db: portalDb } = _getPortal();

// ── Config versioning ────────────────────────────────────────────────────────
// config.js carries a plain, non-secret version label:
//     const PLESSEN_CONFIG_VERSION="20260930T184500Z";
// system/keyFragment holds the current key AND the previous one:
//     { k, ver, prevK, prevVer }
// While Vercel is still deploying a new config.js, the live file is the
// previous version, so the previous key is used — no downtime, no mismatch.
// Files and keys created before versioning count as version "legacy".
export const LEGACY_VERSION = 'legacy';

export function readConfigVersion(fileText) {
  const m = /PLESSEN_CONFIG_VERSION\s*=\s*"([^"]+)"/.exec(fileText || '');
  return m ? m[1] : LEGACY_VERSION;
}

function configError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// Returns { k } for the decrypt script, or throws CONFIG_OUT_OF_DATE.
export function selectKeyForFile(fileText, keyDoc) {
  const fileVer = readConfigVersion(fileText);
  const curVer  = keyDoc.ver || LEGACY_VERSION;
  if (fileVer === curVer && keyDoc.k) return { k: keyDoc.k };
  if (keyDoc.prevK && fileVer === (keyDoc.prevVer || LEGACY_VERSION)) return { k: keyDoc.prevK };
  throw configError('CONFIG_OUT_OF_DATE',
    'config.js is out of date (file v' + fileVer + ', key v' + curVer + '). ' +
    'The new config.js has not been deployed yet — wait for Vercel, or upload the latest config.js from /config-tool.');
}

// Maps any error from loadConfig() / a service sign-in to what a sub-system
// should show. retrySeconds → reload automatically instead of redirecting.
export function describeServiceError(e) {
  const code = (e && (e.code || e.name)) || 'unknown';
  if (code === 'CONFIG_OUT_OF_DATE' || code === 'CONFIG_DECRYPT_FAILED') {
    return { code, retrySeconds: 30, title: 'Configuration Updating',
      message: 'A new system configuration is being deployed. This page will retry automatically. (' + code + ')' };
  }
  if (code === 'LOCATION_NOT_CONFIGURED') {
    return { code, title: 'Location Not Set Up',
      message: (e && e.message) || 'This location has no service accounts yet. A superuser must add them in /config-tool.' };
  }
  if (typeof code === 'string' && code.startsWith('auth/')) {
    return { code, title: 'Service Sign-In Failed',
      message: 'This system could not sign in to its database (' + code + '). Contact your administrator.' };
  }
  return { code, title: 'System Configuration Issue',
    message: 'System configuration issue (' + code + ') — contact your administrator.' };
}

// ── loadConfig() ──────────────────────────────────────────────────────────────
// Resolves with decrypted config object.
// Nulls all sensitive intermediates in finally{} — script, key, blob are
// ephemeral: they exist only during the decrypt operation.
export function loadConfig() {
  return new Promise((resolve, reject) => {

    const unsub = onAuthStateChanged(portalAuth, async (user) => {
      unsub(); // fire once only — do not keep listening

      if (!user) { reject(new Error('NOT_AUTHENTICATED')); return; }

      let script  = null;
      let keyData = null;
      let blob    = null;

      try {
        // Fetch crypto script + key fragment in parallel
        const [cryptoSnap, keySnap] = await Promise.all([
          getDoc(doc(portalDb, 'system', 'crypto')),
          getDoc(doc(portalDb, 'system', 'keyFragment'))
        ]);

        if (!cryptoSnap.exists() || !keySnap.exists()) {
          throw configError('NOT_CONFIGURED', 'NOT_CONFIGURED — open /config-tool to initialise the system.');
        }

        script  = cryptoSnap.data().script;

        // Fetch encrypted config blob (cache-bust so we always get latest)
        const res = await fetch('/config.js?v=' + Date.now());
        if (!res.ok) throw configError('CONFIG_MISSING', 'config.js missing from the site — run /config-tool.');
        blob = await res.text();
        if (blob.includes('PLACEHOLDER_RUN_CONFIG_TOOL')) throw configError('NOT_CONFIGURED', 'config.js is still the placeholder — run /config-tool.');

        // Pick the key that matches the version of the file actually being
        // served (current key, or the previous one during a Vercel deploy).
        keyData = selectKeyForFile(blob, keySnap.data());

        // Execute decryption script in a scoped closure (not on window)
        const decryptFn = (new Function('return (' + script + ')'))();

        // Decrypt → plain config object. Web Crypto's wrong-key error has an
        // EMPTY message, so translate it into something readable.
        let configs;
        try {
          configs = await decryptFn(blob, keyData);
        } catch (de) {
          throw configError('CONFIG_DECRYPT_FAILED',
            'config.js could not be decrypted with the current key (' + (de && (de.name || de.message) || 'unknown') +
            ') — config.js and the Firestore key are out of sync. Regenerate in /config-tool.');
        }
        resolve(configs);

      } catch (e) {
        reject(e);
      } finally {
        // Null sensitive intermediates — they are no longer needed
        script  = null;
        keyData = null;
        blob    = null;
      }
    });
  });
}

// ── initSystemApp() ───────────────────────────────────────────────────────────
// Initialise a sub-project Firebase app from a decrypted config entry.
// Call immediately after loadConfig(), then null your config reference.
export function initSystemApp(cfg, appName) {
  if (getApps().find(a => a.name === appName)) return getApp(appName);
  return initializeApp({
    apiKey:            cfg.apiKey,
    authDomain:        cfg.authDomain,
    projectId:         cfg.projectId,
    storageBucket:     cfg.storageBucket     || '',
    messagingSenderId: cfg.messagingSenderId  || '',
    appId:             cfg.appId,
    ...(cfg.measurementId ? { measurementId: cfg.measurementId } : {})
  }, appName);
}

// ══════════════════════════════════════════════════════════════════════════════
// LOCATIONS — shared by the portal, config-tool and every location-aware system
// ══════════════════════════════════════════════════════════════════════════════
// A location is a site (STX, STT, …) whose data is kept separate inside each
// location-aware system, under sites/{CODE}/… . Locations live in plessen-auth
// `locations/{CODE}` and are managed in the portal (superusers). Nothing in the
// code or the Firestore rules names a location, so adding one is setup only.

// Profiles saved before locations existed hold a single access string per
// system ("editor"); that access belongs to the original site.
export const LEGACY_LOCATION = 'STX';

// Systems whose data is split per location unless their systemConfigs entry
// says otherwise (field `locationAware`).
export const LOCATION_AWARE_DEFAULT = ['equipment', 'inventory'];

export const DEFAULT_LOCATIONS = [
  { code:'STX', name:'St. Croix',  color:'#0f766e', order:1, enabled:true },
  { code:'STT', name:'St. Thomas', color:'#7e22ce', order:2, enabled:true },
];

// Normalise a location code: letters/digits only, upper case, 2–8 characters.
export function normalizeLocationCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
}

// All locations (enabled and disabled), sorted. Falls back to the defaults if
// the registry hasn't been created yet or can't be read.
export async function loadLocations() {
  try {
    const snap = await getDocs(collection(portalDb, 'locations'));
    if (snap.empty) return DEFAULT_LOCATIONS.map(l => ({ ...l }));
    return snap.docs
      .map(d => ({ code: d.id, ...d.data() }))
      .sort((a, b) => (a.order || 99) - (b.order || 99) || a.code.localeCompare(b.code));
  } catch (e) {
    console.warn('[locations] could not read registry, using defaults:', e.code || e.message);
    return DEFAULT_LOCATIONS.map(l => ({ ...l }));
  }
}

export function isLocationAware(sys) {
  if (!sys) return false;
  if (typeof sys.locationAware === 'boolean') return sys.locationAware;
  return LOCATION_AWARE_DEFAULT.includes(sys.key);
}

// A person's access to one location-aware system, as { CODE: 'viewer'|'editor' }.
// Legacy single strings count as access at LEGACY_LOCATION. 'none' is dropped.
export function locationAccessMap(profile, sysKey) {
  const raw = profile && profile.access ? profile.access[sysKey] : undefined;
  const out = {};
  if (!raw) return out;
  if (typeof raw === 'string') {
    if (raw !== 'none') out[LEGACY_LOCATION] = raw;
    return out;
  }
  for (const [code, level] of Object.entries(raw)) {
    if (level === 'viewer' || level === 'editor') out[normalizeLocationCode(code)] = level;
  }
  return out;
}

// Service account emails follow one pattern, which the Firestore rules read
// the location from:  {system}-{location}-admin@  /  {system}-{location}-{role}@
export const SERVICE_DOMAIN = 'plesseneye.com';
// Every location-based system has exactly two accounts per location: admin
// and viewer. The Firestore rules check these exact words — keep them in sync.
export const LOCATION_SECONDARY_ROLE = 'viewer';
export function serviceEmail(sysKey, locCode, kind) {
  return `${String(sysKey).toLowerCase()}-${String(locCode).toLowerCase()}-${kind}@${SERVICE_DOMAIN}`;
}

// Which locations of a location-aware system this person may open, and which
// one to show now. Order of preference: ?loc= in the URL, the current one,
// the last one used on this device, then the first allowed.
//   returns { allowed: [{code,name,color,level}], current: 'STX' | null }
export function resolveLocation(sysKey, profile, locations, current) {
  const map = locationAccessMap(profile, sysKey);
  const allowed = locations
    .filter(l => l.enabled !== false && map[l.code])
    .map(l => ({ code: l.code, name: l.name || l.code, color: l.color || '#64748b', level: map[l.code] }));
  const ok = c => c && allowed.some(a => a.code === c);
  let urlLoc = null, stored = null;
  try { urlLoc = normalizeLocationCode(new URLSearchParams(location.search).get('loc')); } catch (_) {}
  try { stored = localStorage.getItem('pms_loc_' + sysKey); } catch (_) {}
  const pick = [urlLoc, current, stored].find(ok) || (allowed[0] && allowed[0].code) || null;
  return { allowed, current: pick };
}

export function rememberLocation(sysKey, code) {
  try { localStorage.setItem('pms_loc_' + sysKey, code); } catch (_) {}
}

// Header control: a coloured pill for the current location; with two or more
// allowed locations it becomes a dropdown. Self-contained styles so it works
// on any system's header.
export function renderLocationSwitcher(container, allowed, current, onPick) {
  if (!container) return;
  container.innerHTML = '';
  if (!allowed || !allowed.length || !current) { container.style.display = 'none'; return; }
  container.style.display = 'inline-flex';
  if (!document.getElementById('pms-loc-style')) {
    const st = document.createElement('style'); st.id = 'pms-loc-style';
    st.textContent = '@media (max-width:600px){.pms-loc-name{display:none}}';
    document.head.appendChild(st);
  }
  const cur = allowed.find(a => a.code === current) || allowed[0];
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:relative;display:inline-flex;align-items:center';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.title = allowed.length > 1 ? 'Switch location' : 'Location';
  btn.style.cssText = `display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:20px;
    border:1.5px solid ${cur.color};background:${cur.color}26;color:#fff;font:700 12px/1 Inter,-apple-system,sans-serif;
    letter-spacing:.3px;cursor:${allowed.length > 1 ? 'pointer' : 'default'}`;
  btn.innerHTML = `<span style="width:8px;height:8px;border-radius:50%;background:${cur.color};box-shadow:0 0 0 2px #ffffff55"></span>` +
    `<span>${cur.code}</span><span class="pms-loc-name" style="font-weight:500;opacity:.8">${cur.name}</span>` +
    (allowed.length > 1 ? '<span style="opacity:.7;font-size:10px">▾</span>' : '');
  wrap.appendChild(btn);
  if (allowed.length > 1) {
    const menu = document.createElement('div');
    menu.style.cssText = 'position:absolute;top:calc(100% + 6px);left:0;min-width:200px;background:#fff;border-radius:10px;' +
      'box-shadow:0 12px 32px #0004;padding:6px;display:none;z-index:1000';
    for (const a of allowed) {
      const item = document.createElement('button');
      item.type = 'button';
      item.style.cssText = `display:flex;width:100%;align-items:center;gap:8px;padding:8px 10px;border:0;border-radius:7px;
        background:${a.code === cur.code ? '#f1f5f9' : 'transparent'};color:#0f172a;font:600 13px Inter,-apple-system,sans-serif;cursor:pointer;text-align:left`;
      item.innerHTML = `<span style="width:9px;height:9px;border-radius:50%;background:${a.color}"></span>` +
        `<span>${a.code}</span><span style="font-weight:400;color:#64748b">${a.name}</span>` +
        `<span style="margin-left:auto;font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase">${a.level}</span>`;
      item.onclick = (ev) => { ev.stopPropagation(); menu.style.display = 'none'; if (a.code !== cur.code) onPick(a.code); };
      menu.appendChild(item);
    }
    btn.onclick = (ev) => { ev.stopPropagation(); menu.style.display = menu.style.display === 'none' ? 'block' : 'none'; };
    document.addEventListener('click', () => { menu.style.display = 'none'; });
    wrap.appendChild(menu);
  }
  container.appendChild(wrap);
}

// ══════════════════════════════════════════════════════════════════════════════
// ACTIVITY LOG — plessen-auth auditLog/{id}
// ══════════════════════════════════════════════════════════════════════════════
// One append-only record of sign-ins, access, user / system / location / config
// changes and data migrations, from every page. The rules make it trustworthy:
// entries can only be added (never edited or deleted), must name the person
// actually signed in, and must carry the server's own timestamp. Only
// superusers can read it (portal → gear → Activity Log).
//
// Logging never blocks or breaks the app: failures are swallowed.

export const ACTIVITY_CATEGORIES = ['signin','account','access','users','systems','locations','config','security','migration'];

let activityActor = { name: '', role: '' };
let activityContext = { system: 'portal', location: '' };
export function setActivityActor(profile) {
  if (!profile) return;
  activityActor = { name: profile.displayName || '', role: profile.role || '' };
}
export function setActivityContext(ctx) { activityContext = { ...activityContext, ...(ctx || {}) }; }

// "Chrome · Windows" — enough to tell devices apart, nothing identifying.
export function deviceLabel() {
  try {
    const ua = navigator.userAgent || '';
    const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome'
                  : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android'
             : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Other';
    return browser + ' · ' + os;
  } catch (_) { return 'Unknown'; }
}

// Keep details small and plain (no undefined, no functions, strings capped).
function cleanDetails(d) {
  try {
    return JSON.parse(JSON.stringify(d || {}, (k, v) =>
      typeof v === 'string' && v.length > 500 ? v.slice(0, 500) + '…' : v));
  } catch (_) { return {}; }
}

// logActivity('users', 'updated', { target:'jane@…', details:{…} })
// opts.db / opts.auth: use another app's session (the config tool has its own).
export async function logActivity(category, action, info = {}, opts = {}) {
  try {
    const auth = opts.auth || portalAuth;
    const db   = opts.db   || portalDb;
    const user = auth && auth.currentUser;
    if (!user) return;
    await addDoc(collection(db, 'auditLog'), {
      ts: serverTimestamp(),
      actorUid: user.uid,
      actorEmail: user.email || '',
      actorName: info.actorName || activityActor.name || '',
      actorRole: info.actorRole || activityActor.role || '',
      category: String(category),
      action: String(action),
      target: String(info.target || ''),
      system: String(info.system || activityContext.system || ''),
      location: String(info.location !== undefined ? info.location : (activityContext.location || '')),
      details: cleanDetails(info.details),
      device: deviceLabel()
    });
  } catch (e) {
    console.warn('[activity] not recorded:', category, action, e && (e.code || e.message));
  }
}

// Failed sign-in attempts happen with nobody signed in, so the rules accept a
// tiny fixed-shape entry from anyone. Throttled per page so a stuck form or a
// held-down Enter key can't flood the log.
let failedLogTimes = [];
export async function logFailedSignIn(email, reason, opts = {}) {
  try {
    const now = Date.now();
    failedLogTimes = failedLogTimes.filter(t => now - t < 60000);
    if (failedLogTimes.length >= 5) return;          // max 5 per minute per page
    failedLogTimes.push(now);
    const db = opts.db || portalDb;
    await addDoc(collection(db, 'auditLog'), {
      ts: serverTimestamp(),
      category: 'signin',
      action: 'failed',
      email: String(email || '').slice(0, 200),
      reason: String(reason || '').slice(0, 100),
      system: String(opts.system || activityContext.system || 'portal').slice(0, 40),
      device: deviceLabel()
    });
  } catch (e) {
    console.warn('[activity] failed sign-in not recorded:', e && (e.code || e.message));
  }
}

// Field-by-field before → after for the log (only what changed).
export function diffFields(before = {}, after = {}, keys) {
  const out = {};
  const ks = keys || [...new Set([...Object.keys(before || {}), ...Object.keys(after || {})])];
  for (const k of ks) {
    const a = JSON.stringify(before ? before[k] : undefined), b = JSON.stringify(after ? after[k] : undefined);
    if (a !== b) out[k] = { from: before ? before[k] ?? null : null, to: after ? after[k] ?? null : null };
  }
  return out;
}

// Access events from a system page: logs "opened" once, then only real
// changes — "location_switched" or "role_changed". Profile updates that
// change nothing for this system are not logged.
const lastAccess = {};
export function logAccessChange(system, location, role, extra = {}) {
  const prev = lastAccess[system];
  if (prev && prev.location === location && prev.role === role) return;
  lastAccess[system] = { location, role };
  setActivityContext({ system, location: location || '' });
  if (!prev) return logActivity('access', 'opened', { location, details: { role, ...extra } });
  if (prev.location !== location)
    return logActivity('access', 'location_switched', { location, details: { from: prev.location, to: location, role } });
  return logActivity('access', 'role_changed', { location, details: { from: prev.role, to: role } });
}
export function logAccessBlocked(system, reason, location = '') {
  lastAccess[system] = null;
  setActivityContext({ system, location });
  return logActivity('access', 'blocked', { location, details: { reason } });
}

// ══════════════════════════════════════════════════════════════════════════════
// SESSION TIMEOUT — policy in plessen-auth system/sessionPolicy
// ══════════════════════════════════════════════════════════════════════════════
// Every number here is set by superusers in the portal (gear → Security).
// The defaults below are only used until that document exists, or if it is
// unreadable. Nothing in this section is meant to be edited to change policy.
//
//   idleMinutes            sign-out after this long with no activity (people)
//   genericIdleMinutes     same, for shared-device (generic) accounts
//   maxSessionHours        hard limit after sign-in, even while active
//   warnSeconds            countdown shown before an automatic sign-out
//   signOutOnBrowserClose  closing the browser ends the session
//
// Activity in any open PMS tab keeps every tab alive (shared via localStorage).

export const SESSION_POLICY_DOC = ['system', 'sessionPolicy'];
export const SESSION_POLICY_DEFAULTS = Object.freeze({
  idleMinutes: 30, genericIdleMinutes: 10, maxSessionHours: 8, warnSeconds: 60, signOutOnBrowserClose: true
});
export const SESSION_POLICY_LIMITS = Object.freeze({
  idleMinutes:        { min: 1,  max: 480, unit: 'minutes' },
  genericIdleMinutes: { min: 1,  max: 480, unit: 'minutes' },
  maxSessionHours:    { min: 1,  max: 24,  unit: 'hours'   },
  warnSeconds:        { min: 10, max: 600, unit: 'seconds' }
});

// Strict check for the Security screen: returns { ok, policy, errors{field:msg} }.
export function validateSessionPolicy(input = {}) {
  const errors = {}, policy = {};
  for (const [k, lim] of Object.entries(SESSION_POLICY_LIMITS)) {
    const raw = input[k];
    const n = (raw === '' || raw === null || raw === undefined) ? NaN : Number(raw);
    if (!Number.isInteger(n)) errors[k] = 'Enter a whole number';
    else if (n < lim.min || n > lim.max) errors[k] = `Must be ${lim.min}–${lim.max} ${lim.unit}`;
    policy[k] = n;
  }
  policy.signOutOnBrowserClose = typeof input.signOutOnBrowserClose === 'boolean'
    ? input.signOutOnBrowserClose : SESSION_POLICY_DEFAULTS.signOutOnBrowserClose;
  const longestIdle = Math.max(policy.idleMinutes, policy.genericIdleMinutes);
  if (!errors.maxSessionHours && !errors.idleMinutes && !errors.genericIdleMinutes
      && policy.maxSessionHours * 60 < longestIdle)
    errors.maxSessionHours = 'Must be at least as long as the idle limits';
  const shortestIdle = Math.min(policy.idleMinutes, policy.genericIdleMinutes);
  if (!errors.warnSeconds && !errors.idleMinutes && !errors.genericIdleMinutes
      && policy.warnSeconds >= shortestIdle * 60)
    errors.warnSeconds = 'Must be shorter than the idle limits';
  return { ok: Object.keys(errors).length === 0, policy, errors };
}

// Forgiving version for whatever is stored: a bad or partial document never
// breaks sign-out. Bad fields fall back to the default; conflicts are repaired.
export function normalizeSessionPolicy(raw) {
  const out = { ...SESSION_POLICY_DEFAULTS };
  if (raw && typeof raw === 'object') {
    for (const [k, lim] of Object.entries(SESSION_POLICY_LIMITS)) {
      const n = Number(raw[k]);
      if (Number.isInteger(n) && n >= lim.min && n <= lim.max) out[k] = n;
    }
    if (typeof raw.signOutOnBrowserClose === 'boolean') out.signOutOnBrowserClose = raw.signOutOnBrowserClose;
  }
  const longestIdle = Math.max(out.idleMinutes, out.genericIdleMinutes);
  if (out.maxSessionHours * 60 < longestIdle) out.maxSessionHours = Math.min(24, Math.ceil(longestIdle / 60));
  const shortestIdle = Math.min(out.idleMinutes, out.genericIdleMinutes);
  if (out.warnSeconds >= shortestIdle * 60) out.warnSeconds = Math.max(5, Math.floor(shortestIdle * 60 / 2));
  return out;
}

export function describeSessionPolicy(p, isGeneric = false) {
  const m = isGeneric ? p.genericIdleMinutes : p.idleMinutes;
  return `Auto sign-out after ${m} min idle`;
}

const SG_LAST    = uid => 'pms_last_'  + uid;   // last activity (any tab)
const SG_START   = uid => 'pms_start_' + uid;   // sign-in time fallback
const SG_LOGLOCK = uid => 'pms_tolog_' + uid;   // one timeout entry, not one per tab
const SG_NOTICE  = 'pms_signout_notice';
const SG_COOKIE  = 'pms_bs';                    // browser-session cookie (no expiry)
const sgNum  = k => { try { const n = Number(localStorage.getItem(k)); return Number.isFinite(n) && n > 0 ? n : 0; } catch (_) { return 0; } };
const sgSet  = (k, v) => { try { localStorage.setItem(k, String(v)); } catch (_) {} };
const sgWait = ms => new Promise(r => setTimeout(r, ms));

function sgHasCookie(uid) {
  try { return document.cookie.split(';').some(c => c.trim() === `${SG_COOKIE}=${encodeURIComponent(uid)}`); }
  catch (_) { return true; }
}
function sgClearCookie() {
  try { document.cookie = `${SG_COOKIE}=; path=/; max-age=0; SameSite=Strict`; } catch (_) {}
}

// Call right after a REAL sign-in (not a page reload). Starts the clocks and
// drops the browser-session cookie the browser removes when it is closed.
export function markSessionStart(uid) {
  if (!uid) return;
  const now = Date.now();
  sgSet(SG_LAST(uid), now);
  sgSet(SG_START(uid), now);
  try { localStorage.removeItem(SG_NOTICE); } catch (_) {}
  try {
    document.cookie = `${SG_COOKIE}=${encodeURIComponent(uid)}; path=/; SameSite=Strict` +
      (location.protocol === 'https:' ? '; Secure' : '');
  } catch (_) {}
}

// The portal's sign-in screen shows why someone was signed out (once).
export function takeSignOutNotice() {
  try {
    const raw = localStorage.getItem(SG_NOTICE);
    localStorage.removeItem(SG_NOTICE);
    if (!raw) return '';
    const n = JSON.parse(raw);
    if (!n || Date.now() - (n.at || 0) > 12 * 3600 * 1000) return '';
    if (n.reason === 'idle')          return `You were signed out after ${n.minutes} minutes without activity.`;
    if (n.reason === 'max')           return `Your ${n.hours}-hour session limit was reached. Please sign in again.`;
    if (n.reason === 'browser-close') return 'You were signed out because the browser was closed. Please sign in again.';
    if (n.reason === 'new-policy')    return 'New sign-in security settings are in effect. Please sign in again.';
    return '';
  } catch (_) { return ''; }
}

// ── Warning dialog (self-contained styles) ───────────────────────────────────
function sgFmt(ms) { const s = Math.max(0, Math.ceil(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }
function sgBuildDialog() {
  const wrap = document.createElement('div');
  wrap.setAttribute('role', 'alertdialog');
  wrap.setAttribute('aria-modal', 'true');
  wrap.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(15,23,42,.55);display:flex;' +
    'align-items:center;justify-content:center;padding:16px;font-family:Inter,-apple-system,Segoe UI,sans-serif';
  wrap.innerHTML =
    '<div style="background:#fff;border-radius:14px;max-width:380px;width:100%;padding:22px 22px 18px;box-shadow:0 24px 60px rgba(0,0,0,.35);color:#0f172a">' +
      '<div data-sg="title" style="font-size:17px;font-weight:800;margin-bottom:6px"></div>' +
      '<div data-sg="body" style="font-size:14px;line-height:1.5;color:#475569"></div>' +
      '<div data-sg="count" style="font-size:34px;font-weight:800;letter-spacing:1px;margin:14px 0 16px;color:#b45309;font-variant-numeric:tabular-nums"></div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap">' +
        '<button type="button" data-sg="out" style="padding:9px 14px;border-radius:9px;border:1.5px solid #e2e8f0;background:#fff;color:#475569;font:600 13px Inter,-apple-system,Segoe UI,sans-serif;cursor:pointer">Sign out now</button>' +
        '<button type="button" data-sg="stay" style="padding:9px 16px;border-radius:9px;border:0;background:#1d4ed8;color:#fff;font:700 13px Inter,-apple-system,Segoe UI,sans-serif;cursor:pointer"></button>' +
      '</div>' +
    '</div>';
  return wrap;
}

// ── The guard ────────────────────────────────────────────────────────────────
// startSessionGuard({ profile, system, signOut, beforeSignOut })
//   profile        portal profile (role 'generic' → generic idle limit)
//   signOut        the page's own Sign Out (used by "Sign out now")
//   beforeSignOut  async hook run before an automatic sign-out (flush saves)
//   auth / db      another app's session (config tool); default: portal
//   redirectTo     where to go after an automatic sign-out (default: portal)
// Returns { setProfile, stop, policy() }. Safe to call again (updates profile).
let activeGuard = null;
const gearNoteEls = new Set();
let gearNoteText = '';
function setGearNote(t) {
  gearNoteText = t;
  for (const el of gearNoteEls) { if (el.isConnected) el.textContent = t; else gearNoteEls.delete(el); }
}

// Show "Auto sign-out after N min idle" in a page's own menu (the portal's).
export function bindSessionNote(el) { if (!el) return; gearNoteEls.add(el); el.textContent = gearNoteText; }

export function startSessionGuard(opts = {}) {
  if (activeGuard) { if (opts.profile) activeGuard.setProfile(opts.profile); return activeGuard; }
  const auth = opts.auth || portalAuth;
  const db   = opts.db   || portalDb;
  const user = auth.currentUser;
  if (!user) return null;
  const uid = user.uid;
  let profile = opts.profile || null;
  let policy = { ...SESSION_POLICY_DEFAULTS };
  let started = false, stopped = false, firing = false, timer = null, unsubPolicy = null;
  let dialog = null, dialogMode = '', maxWarnDismissed = false, lastWrite = 0;

  const isGeneric = () => !!profile && profile.role === 'generic';
  const idleMs = () => (isGeneric() ? policy.genericIdleMinutes : policy.idleMinutes) * 60000;
  const maxMs  = () => policy.maxSessionHours * 3600000;
  const signInAt = () => {
    const t = Date.parse((user.metadata && user.metadata.lastSignInTime) || '');
    if (Number.isFinite(t) && t > 0) return t;
    let s = sgNum(SG_START(uid)); if (!s) { s = Date.now(); sgSet(SG_START(uid), s); }
    return s;
  };
  const lastActive = () => { let l = sgNum(SG_LAST(uid)); if (!l) { l = Date.now(); sgSet(SG_LAST(uid), l); } return l; };
  const refreshNote = () => setGearNote(describeSessionPolicy(policy, isGeneric()));

  function onActivity() {
    if (stopped || dialog) return;               // during a warning only the button counts
    const now = Date.now();
    if (now - lastWrite < 5000) return;
    lastWrite = now;
    sgSet(SG_LAST(uid), now);
  }
  const EVENTS = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel'];
  const onVisible = () => { if (document.visibilityState === 'visible') check(); };

  function hideDialog() { if (dialog) { dialog.remove(); dialog = null; dialogMode = ''; } }
  function showDialog(mode, msLeft) {
    if (mode === 'max' && maxWarnDismissed) { hideDialog(); return; }
    if (!dialog || dialogMode !== mode) {
      hideDialog();
      dialog = sgBuildDialog(); dialogMode = mode;
      const q = s => dialog.querySelector(`[data-sg="${s}"]`);
      if (mode === 'idle') {
        q('title').textContent = 'Are you still there?';
        q('body').textContent  = 'For security you will be signed out because of inactivity.';
        q('stay').textContent  = 'Stay signed in';
        q('stay').onclick = () => { sgSet(SG_LAST(uid), Date.now()); lastWrite = Date.now(); hideDialog(); };
      } else {
        q('title').textContent = 'Session limit reached soon';
        q('body').textContent  = `Sessions last at most ${policy.maxSessionHours} hours. Finish what you are doing — you will need to sign in again.`;
        q('stay').textContent  = 'OK';
        q('stay').onclick = () => { maxWarnDismissed = true; hideDialog(); };
      }
      q('out').onclick = () => { stop(); hideDialog(); (opts.signOut ? Promise.resolve(opts.signOut()) : fbSignOut(auth).then(() => { window.location.href = opts.redirectTo || '/'; })).catch(() => {}); };
      document.body.appendChild(dialog);
      setTimeout(() => { try { q('stay').focus(); } catch (_) {} }, 0);
    }
    dialog.querySelector('[data-sg="count"]').textContent = sgFmt(msLeft);
  }

  function check() {
    if (!started || stopped || firing) return;
    if (!auth.currentUser || auth.currentUser.uid !== uid) { stop(); hideDialog(); return; }   // signed out elsewhere
    const now = Date.now();
    const idleLeft = lastActive() + idleMs() - now;
    const maxLeft  = signInAt() + maxMs() - now;
    if (maxLeft <= 0)  return fire('max');
    if (idleLeft <= 0) return fire('idle');
    const warn = policy.warnSeconds * 1000;
    if (maxLeft <= warn && maxLeft <= idleLeft) showDialog('max', maxLeft);
    else if (idleLeft <= warn) showDialog('idle', idleLeft);
    else hideDialog();
  }

  async function fire(reason) {
    if (firing) return;
    firing = true;
    const minutes = idleMs() / 60000;
    stop();
    hideDialog();
    try { localStorage.setItem(SG_NOTICE, JSON.stringify({ reason, minutes, hours: policy.maxSessionHours, at: Date.now() })); } catch (_) {}
    try { if (opts.beforeSignOut) await Promise.race([Promise.resolve(opts.beforeSignOut(reason)), sgWait(5000)]); } catch (_) {}
    let logIt = true;
    try {
      const prev = sgNum(SG_LOGLOCK(uid));
      if (Date.now() - prev < 15000) logIt = false; else sgSet(SG_LOGLOCK(uid), Date.now());
    } catch (_) {}
    if (logIt) {
      await Promise.race([
        logActivity('signin', 'timeout', { target: user.email || '', system: opts.system,
          details: { reason, idleMinutes: minutes, maxSessionHours: policy.maxSessionHours, generic: isGeneric() } }, { auth, db }),
        sgWait(3000)
      ]);
    }
    try { await fbSignOut(auth); } catch (_) {}
    sgClearCookie();
    window.location.href = opts.redirectTo || '/';
  }

  function stop() {
    stopped = true;
    if (timer) { clearInterval(timer); timer = null; }
    if (unsubPolicy) { try { unsubPolicy(); } catch (_) {} unsubPolicy = null; }
    EVENTS.forEach(ev => window.removeEventListener(ev, onActivity, true));
    document.removeEventListener('visibilitychange', onVisible);
    if (activeGuard === api) activeGuard = null;
  }

  function begin() {
    if (started || stopped) return;
    started = true;
    refreshNote();
    // Checks that only make sense when a page first opens.
    if (policy.signOutOnBrowserClose && !sgHasCookie(uid)) {
      // No cookie and no record of a sign-in on this browser: the session
      // predates this feature. Otherwise the browser was closed and reopened.
      return fire(sgNum(SG_START(uid)) ? 'browser-close' : 'new-policy');
    }
    check();
    if (!stopped) timer = setInterval(check, 1000);
  }

  EVENTS.forEach(ev => window.addEventListener(ev, onActivity, { capture: true, passive: true }));
  document.addEventListener('visibilitychange', onVisible);
  try {
    unsubPolicy = onSnapshot(doc(db, ...SESSION_POLICY_DOC),
      snap => { policy = normalizeSessionPolicy(snap.exists() ? snap.data() : null); maxWarnDismissed = false; refreshNote(); begin(); check(); },
      ()   => { begin(); });
  } catch (_) { begin(); }
  setTimeout(begin, 5000);   // policy unreachable → defaults, never "no timeout"

  const api = {
    setProfile(p) { profile = p || profile; refreshNote(); check(); },
    stop,
    policy: () => ({ ...policy })
  };
  activeGuard = api;
  return api;
}

// ══════════════════════════════════════════════════════════════════════════════
// SHARED GEAR MENU — top-left of every system's header
// ══════════════════════════════════════════════════════════════════════════════
// mountGearMenu(container, {
//   theme: 'dark' | 'onColor',            // dark app (Equipment) or coloured header
//   identity: { name, detail },           // "who you are"
//   sections: [{ label, items: [{ id, label, icon, onClick, hidden }] }],
//   onSignOut                              // Sign Out is always last, in red
// }) → { setIdentity({name, detail}), close(), el }
const GEAR_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
const SIGNOUT_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
export const GEAR_ICONS = {
  settings: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>',
  key:      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  download: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  mail:     '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22 6 12 13 2 6"/></svg>'
};

function gearStyles() {
  if (document.getElementById('pms-gear-style')) return;
  const st = document.createElement('style');
  st.id = 'pms-gear-style';
  st.textContent = `
.pms-gear{position:relative;display:inline-flex;flex-shrink:0;font-family:Inter,-apple-system,Segoe UI,sans-serif}
.pms-gear-btn{width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,color .15s}
.pms-gear.onColor .pms-gear-btn{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.28);color:#fff}
.pms-gear.onColor .pms-gear-btn:hover,.pms-gear.onColor .pms-gear-btn[aria-expanded="true"]{background:rgba(255,255,255,.26)}
.pms-gear.dark .pms-gear-btn{background:transparent;border:1px solid #1e2035;color:#94a3b8}
.pms-gear.dark .pms-gear-btn:hover,.pms-gear.dark .pms-gear-btn[aria-expanded="true"]{background:#1e2035;color:#e2e8f0}
.pms-gear-menu{position:absolute;top:calc(100% + 8px);left:0;min-width:240px;max-width:calc(100vw - 24px);border-radius:12px;padding:6px;z-index:1000;box-shadow:0 16px 40px rgba(0,0,0,.28)}
.pms-gear-menu[hidden]{display:none}
.pms-gear.onColor .pms-gear-menu{background:#fff;border:1px solid #e2e8f0;color:#0f172a}
.pms-gear.dark .pms-gear-menu{background:#13132a;border:1px solid #1e2035;color:#e2e8f0}
.pms-gear-who{padding:9px 11px 8px}
.pms-gear-name{font-size:13px;font-weight:700}
.pms-gear-detail{font-size:11.5px;margin-top:2px;opacity:.7}
.pms-gear-note{font-size:11px;margin-top:5px;display:flex;align-items:center;gap:5px;opacity:.65}
.pms-gear-note:empty{display:none}
.pms-gear-sec{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;padding:8px 11px 4px;opacity:.55}
.pms-gear-item{display:flex;align-items:center;gap:9px;width:100%;padding:8px 11px;border:0;border-radius:8px;background:transparent;color:inherit;font:500 13px Inter,-apple-system,Segoe UI,sans-serif;text-align:left;cursor:pointer}
.pms-gear.onColor .pms-gear-item:hover{background:#eff6ff}
.pms-gear.dark .pms-gear-item:hover{background:#1e2035}
.pms-gear-div{height:1px;margin:5px 0}
.pms-gear.onColor .pms-gear-div{background:#e2e8f0}
.pms-gear.dark .pms-gear-div{background:#1e2035}
.pms-gear-item.pms-signout{color:#dc2626;font-weight:600}
.pms-gear.dark .pms-gear-item.pms-signout{color:#fca5a5}
.pms-gear.onColor .pms-gear-item.pms-signout:hover{background:#fef2f2}
.pms-gear.dark .pms-gear-item.pms-signout:hover{background:#7f1d1d44}`;
  document.head.appendChild(st);
}

export function mountGearMenu(container, opts = {}) {
  if (!container) return null;
  gearStyles();
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  container.innerHTML = '';
  const root = document.createElement('div');
  root.className = 'pms-gear ' + (opts.theme === 'dark' ? 'dark' : 'onColor');
  const btn = document.createElement('button');
  btn.type = 'button'; btn.className = 'pms-gear-btn'; btn.title = 'Settings';
  btn.setAttribute('aria-haspopup', 'menu'); btn.setAttribute('aria-expanded', 'false');
  btn.innerHTML = GEAR_SVG;
  const menu = document.createElement('div');
  menu.className = 'pms-gear-menu'; menu.setAttribute('role', 'menu'); menu.hidden = true;

  const who = document.createElement('div');
  who.className = 'pms-gear-who';
  who.innerHTML = '<div class="pms-gear-name"></div><div class="pms-gear-detail"></div><div class="pms-gear-note"></div>';
  menu.appendChild(who);
  const note = who.querySelector('.pms-gear-note');
  note.textContent = gearNoteText;
  gearNoteEls.add(note);

  const groups = [];
  const close = () => { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  const open  = () => {
    // A section whose items are all hidden for this role disappears entirely.
    for (const g of groups) g.style.display = [...g.querySelectorAll('.pms-gear-item')].some(b => b.style.display !== 'none') ? '' : 'none';
    menu.hidden = false; btn.setAttribute('aria-expanded', 'true');
  };
  const addItem = (it, cls, parent = menu) => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'pms-gear-item' + (cls ? ' ' + cls : ''); b.setAttribute('role', 'menuitem');
    if (it.id) b.id = it.id;
    if (it.hidden) b.style.display = 'none';
    b.innerHTML = (it.icon || '') + '<span>' + esc(it.label) + '</span>';
    b.onclick = (ev) => { ev.stopPropagation(); close(); try { it.onClick && it.onClick(); } catch (e) { console.error(e); } };
    parent.appendChild(b);
    return b;
  };
  for (const sec of (opts.sections || [])) {
    if (!sec || !(sec.items || []).length) continue;
    const g = document.createElement('div'); g.className = 'pms-gear-group';
    const d = document.createElement('div'); d.className = 'pms-gear-div'; g.appendChild(d);
    if (sec.label) { const l = document.createElement('div'); l.className = 'pms-gear-sec'; l.textContent = sec.label; g.appendChild(l); }
    sec.items.forEach(it => addItem(it, '', g));
    menu.appendChild(g); groups.push(g);
  }
  const d = document.createElement('div'); d.className = 'pms-gear-div'; menu.appendChild(d);
  addItem({ label: 'Sign Out', icon: SIGNOUT_SVG, onClick: opts.onSignOut }, 'pms-signout');

  btn.onclick = (ev) => { ev.stopPropagation(); menu.hidden ? open() : close(); };
  menu.addEventListener('click', ev => ev.stopPropagation());
  if (!container._pmsGearDoc) {
    container._pmsGearDoc = true;
    document.addEventListener('click', () => container._pmsGearClose && container._pmsGearClose());
    document.addEventListener('keydown', ev => { if (ev.key === 'Escape' && container._pmsGearClose) container._pmsGearClose(); });
  }
  container._pmsGearClose = close;
  root.appendChild(btn); root.appendChild(menu);
  container.appendChild(root);

  const setIdentity = (id = {}) => {
    who.querySelector('.pms-gear-name').textContent   = id.name || '—';
    who.querySelector('.pms-gear-detail').textContent = id.detail || '';
  };
  setIdentity(opts.identity);
  return { setIdentity, close, el: root };
}

// ══════════════════════════════════════════════════════════════════════════════
// INVENTORY POLICY — plessen-auth system/inventoryPolicy (portal → Security)
// ══════════════════════════════════════════════════════════════════════════════
//   techUndoEnabled   staff (viewer) may undo their removals
//   techUndoMinutes   how long after a removal staff may undo it
// Admins have no Undo button — they correct quantities in the edit menu.
// The Inventory database rules allow staff undo up to INVENTORY_UNDO_CEILING_MIN
// at most, so the largest value accepted here matches that ceiling.
export const INVENTORY_POLICY_DOC = ['system', 'inventoryPolicy'];
export const INVENTORY_UNDO_CEILING_MIN = 1440;   // 24 h — same number as in plessen-inventory.rules
export const INVENTORY_POLICY_DEFAULTS = Object.freeze({ techUndoEnabled: true, techUndoMinutes: 30 });
export const INVENTORY_POLICY_LIMITS = Object.freeze({ techUndoMinutes: { min: 1, max: INVENTORY_UNDO_CEILING_MIN, unit: 'minutes' } });

export function validateInventoryPolicy(input = {}) {
  const errors = {}, policy = {};
  const raw = input.techUndoMinutes;
  const n = (raw === '' || raw === null || raw === undefined) ? NaN : Number(raw);
  const L = INVENTORY_POLICY_LIMITS.techUndoMinutes;
  if (!Number.isInteger(n)) errors.techUndoMinutes = 'Enter a whole number';
  else if (n < L.min || n > L.max) errors.techUndoMinutes = `Must be ${L.min}–${L.max} minutes`;
  policy.techUndoMinutes = n;
  policy.techUndoEnabled = typeof input.techUndoEnabled === 'boolean' ? input.techUndoEnabled : INVENTORY_POLICY_DEFAULTS.techUndoEnabled;
  return { ok: !Object.keys(errors).length, policy, errors };
}
export function normalizeInventoryPolicy(raw) {
  const out = { ...INVENTORY_POLICY_DEFAULTS };
  if (raw && typeof raw === 'object') {
    const n = Number(raw.techUndoMinutes), L = INVENTORY_POLICY_LIMITS.techUndoMinutes;
    if (Number.isInteger(n) && n >= L.min && n <= L.max) out.techUndoMinutes = n;
    if (typeof raw.techUndoEnabled === 'boolean') out.techUndoEnabled = raw.techUndoEnabled;
  }
  return out;
}
// Live copy for the Inventory page. Unreadable → defaults (never "unlimited").
export function watchInventoryPolicy(cb, db = portalDb) {
  cb({ ...INVENTORY_POLICY_DEFAULTS });
  try {
    return onSnapshot(doc(db, ...INVENTORY_POLICY_DOC),
      snap => cb(normalizeInventoryPolicy(snap.exists() ? snap.data() : null)),
      () => cb({ ...INVENTORY_POLICY_DEFAULTS }));
  } catch (_) { return () => {}; }
}
