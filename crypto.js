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
          throw new Error('NOT_CONFIGURED — open /config-tool to initialise the system.');
        }

        script  = cryptoSnap.data().script;
        keyData = keySnap.data();

        // Fetch encrypted config blob (cache-bust so we always get latest)
        const res = await fetch('/config.js?v=' + Date.now());
        if (!res.ok) throw new Error('config.js missing from repo — run config-tool.');
        blob = await res.text();

        // Execute decryption script in a scoped closure (not on window)
        const decryptFn = (new Function('return (' + script + ')'))();

        // Decrypt → plain config object
        const configs = await decryptFn(blob, keyData);
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
