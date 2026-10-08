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
import { getFirestore, doc, getDoc }
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
