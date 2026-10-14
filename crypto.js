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
import { getAuth, onAuthStateChanged }
  from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js';
import { getFirestore, doc, getDoc, getDocs, collection, addDoc, serverTimestamp }
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
    `<span>${cur.code}</span><span style="font-weight:500;opacity:.8">${cur.name}</span>` +
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

export const ACTIVITY_CATEGORIES = ['signin','account','access','users','systems','locations','config','migration'];

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
