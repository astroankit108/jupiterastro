/* =========================================================
   JUPITER ASTRO — FIREBASE AUTHENTICATION BRIDGE
   Firebase identifies the user. Cloudflare establishes the
   signed, HttpOnly website session after server-side checks.

   Load before Account.js and Email Verification.js.
   ========================================================= */

import { initializeApp } from
  "https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js";

import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  signOut,
  onAuthStateChanged,
  onIdTokenChanged,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  reload
} from
  "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyDwXS6894YgdyuD9-3ThCwsDiSHkyuNFpU",
  authDomain: "jupiter-astro.firebaseapp.com",
  projectId: "jupiter-astro",
  storageBucket: "jupiter-astro.firebasestorage.app",
  messagingSenderId: "867320173550",
  appId: "1:867320173550:web:fead03b3b96c8fd01034ff"
};

window.jaFirebaseConfig = {
  apiKey: firebaseConfig.apiKey,
  driveApiKey: "AIzaSyB5sipi-7bK2k-VWblZ9g4Lf1_uPSx1NXY",
  projectId: firebaseConfig.projectId
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

window.firebaseAuth = auth;
window.firebaseAuthAPI = {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  signOut,
  onAuthStateChanged,
  onIdTokenChanged,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  reload
};

// ---------------- Public auth state ----------------

window.jaAuthUser = null;
window.jaAuthStateReady = false;

let resolveJaAuthReady;
window.jaAuthReady = new Promise(resolve => {
  resolveJaAuthReady = resolve;
});

function publishJaAuthState(user) {
  window.jaAuthUser = user || null;
  if (!window.jaAuthStateReady) {
    window.jaAuthStateReady = true;
    resolveJaAuthReady?.(window.jaAuthUser);
    resolveJaAuthReady = null;
  }
  window.dispatchEvent(new CustomEvent("ja-auth-state-changed", {
    detail: { user: window.jaAuthUser }
  }));
}

// ---------------- Account button ----------------

const accountButton = document.getElementById("accountOpenBtn");
const defaultAccountIcon = `
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="8" r="4"/>
    <path d="M5 21a7 7 0 0 1 14 0"/>
  </svg>`;

function updateAccountButton(user) {
  if (!accountButton) return;
  if (user?.email) {
    const initial = String(user.email).trim().charAt(0).toUpperCase() || "?";
    accountButton.classList.add("is-logged-in");
    accountButton.innerHTML = '<span class="account-user-initial" aria-hidden="true">' + initial + '</span>';
    accountButton.title = 'Logged in as "' + user.email + '"';
    accountButton.setAttribute("aria-label", 'Logged in as "' + user.email + '"');
    accountButton.setAttribute("data-user-email", user.email);
  } else {
    accountButton.classList.remove("is-logged-in");
    accountButton.innerHTML = defaultAccountIcon;
    accountButton.title = "Account";
    accountButton.setAttribute("aria-label", "Open account");
    accountButton.removeAttribute("data-user-email");
  }
}

// Copy/export is available only after the Cloudflare session has succeeded.
function syncCopyExportAccess(user) {
  const locked = !user;
  document.querySelectorAll(".copy-export-control").forEach(control => {
    control.classList.toggle("ja-auth-locked", locked);
    if (locked) {
      const menu = control.querySelector(".copy-export-menu");
      const trigger = control.querySelector(".copy-export-trigger");
      if (menu) menu.hidden = true;
      trigger?.setAttribute("aria-expanded", "false");
    }
  });
}

// Capture before existing copy/export handlers.
document.addEventListener("click", event => {
  if (window.jaAuthUser) return;
  const control = event.target?.closest?.(".copy-export-control");
  if (!control) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  document.getElementById("accountOpenBtn")?.click();
}, true);

const copyExportObserver = new MutationObserver(() => {
  syncCopyExportAccess(window.jaAuthUser);
});
copyExportObserver.observe(document.documentElement, { childList: true, subtree: true });

// ---------------- Cloudflare session bridge ----------------

let sessionExchangePromise = null;
let logoutCleanupPromise = null;
let lastFirebaseUid = null;

function makeAuthError(message, code, status) {
  const error = new Error(message || "Could not establish a secure website session.");
  error.code = code || "JA_SESSION_FAILED";
  error.status = Number(status || 0);
  return error;
}

async function readJsonResponse(response) {
  const raw = await response.text();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (_) {
    throw makeAuthError(
      "The secure login service returned an unreadable response. Please try again.",
      "JA_SESSION_BAD_RESPONSE",
      response.status
    );
  }
}

window.jaEnsureCloudflareSession = function (user) {
  if (!user?.uid) {
    return Promise.reject(makeAuthError("Please sign in to access Jupiter Astro.", "JA_NO_FIREBASE_USER", 401));
  }

  // Account.js and onIdTokenChanged can both request the exchange.
  // Share one in-flight operation so only one session POST is sent.
  if (sessionExchangePromise) return sessionExchangePromise;

  const uid = user.uid;
  sessionExchangePromise = (async () => {
    await reload(user);

    if (user.emailVerified !== true) {
      throw makeAuthError(
        "Please verify your email address before accessing Jupiter Astro.",
        "JA_EMAIL_NOT_VERIFIED",
        403
      );
    }

    // Force-refresh the Firebase ID token before the server exchange.
    const idToken = await user.getIdToken(true);
    if (typeof idToken !== "string" || idToken.length < 100) {
      throw makeAuthError("Firebase did not provide a valid sign-in token. Please sign in again.", "JA_ID_TOKEN_MISSING", 401);
    }

    let response;
    try {
      response = await fetch("/__auth/session", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ idToken })
      });
    } catch (_) {
      throw makeAuthError(
        "The secure login service could not be reached. Check your connection and try again.",
        "JA_SESSION_NETWORK_ERROR",
        0
      );
    }

    const result = await readJsonResponse(response);
    if (!response.ok || result.success !== true) {
      throw makeAuthError(
        result.error || "Could not establish a secure website session.",
        result.code || "JA_SESSION_REJECTED",
        response.status
      );
    }

    window.dispatchEvent(new CustomEvent("ja-cloudflare-session-ready", {
      detail: { email: user.email || "", expiresAt: result.expiresAt || null }
    }));
    return result;
  })().finally(() => {
    sessionExchangePromise = null;
  });

  return sessionExchangePromise;
};

async function clearCloudflareSession() {
  if (logoutCleanupPromise) return logoutCleanupPromise;
  logoutCleanupPromise = (async () => {
    try {
      await fetch("/__auth/logout", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
    } catch (error) {
      console.warn("Jupiter Astro: Cloudflare session cleanup could not reach the Worker.", error);
    }
  })().finally(() => {
    logoutCleanupPromise = null;
  });
  return logoutCleanupPromise;
}

// All sign-out paths use this helper. The auth listener and caller share
// the same cleanup promise, avoiding duplicate /__auth/logout requests.
window.jaSignOut = async function () {
  await signOut(auth);
  await clearCloudflareSession();
};

// ---------------- Single auth-state coordinator ----------------

onIdTokenChanged(auth, async user => {
  if (!user) {
    const shouldClearCookie = Boolean(lastFirebaseUid);
    lastFirebaseUid = null;
    publishJaAuthState(null);
    updateAccountButton(null);
    syncCopyExportAccess(null);
    if (shouldClearCookie) await clearCloudflareSession();
    return;
  }

  if (lastFirebaseUid && lastFirebaseUid !== user.uid) {
    await clearCloudflareSession();
  }
  lastFirebaseUid = user.uid;

  // Newly-created accounts are intentionally not logged into the protected
  // application until the verification link has been used. This also lets
  // Account.js send the verification email before signing the user out.
  if (user.emailVerified !== true) {
    publishJaAuthState(null);
    updateAccountButton(null);
    syncCopyExportAccess(null);
    return;
  }

  try {
    await window.jaEnsureCloudflareSession(user);
    // Do not publish a logged-in state until the Worker has set its cookie.
    publishJaAuthState(user);
    updateAccountButton(user);
    syncCopyExportAccess(user);
  } catch (error) {
    console.error("Jupiter Astro: Cloudflare session establishment failed.", {
      code: error.code || "JA_SESSION_FAILED",
      status: error.status || 0,
      message: error.message
    });

    publishJaAuthState(null);
    updateAccountButton(null);
    syncCopyExportAccess(null);

    // Definitive authentication/authorization failures should clear the
    // Firebase identity too. A 503/network problem is transient: retain the
    // Firebase user so the user can retry without entering credentials again.
    if (error.status === 401 || error.status === 403) {
      try { await signOut(auth); } catch (signOutError) {
        console.error("Jupiter Astro: Firebase sign-out after rejected session failed.", signOutError);
      }
    }
  }
});

console.info("Jupiter Astro: Firebase authentication bridge initialized.");
