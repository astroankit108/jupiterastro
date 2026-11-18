
/* =========================================================
   JUPITER ASTRO — FIREBASE
   Firebase SDK initialisation and auth-session synchronisation.
   Load this module before Account.js and Email Verification.js.
   ========================================================= */

// ================= FIREBASE SDK IMPORTS =================

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


// ================= FIREBASE CONFIGURATION =================

const firebaseConfig = {
  apiKey: "AIzaSyDwXS689Y4gdyuD9-3ThCwsDiSHkyuNFpU",
  authDomain: "jupiter-astro.firebaseapp.com",
  projectId: "jupiter-astro",
  storageBucket: "jupiter-astro.firebasestorage.app",
  messagingSenderId: "867320173550",
  appId: "1:867320173550:web:fead03b3b96c8fd01034ff"
};


// Public client configuration for browser-side integrations.
window.jaFirebaseConfig = {
  apiKey: firebaseConfig.apiKey,

  // Dedicated Google Drive API key.
  // Restrict this key by HTTP referrer and enabled APIs.
  driveApiKey: "AIzaSyB5sipi-7bK2k-VWblZ9g4Lf1_uPSx1NXY",

  projectId: firebaseConfig.projectId
};


// ================= INITIALIZE FIREBASE =================

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);


// ================= EXPOSE AUTHENTICATION FUNCTIONS =================

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


// ================= ACCOUNT SESSION SYNCHRONIZATION =================

window.jaAuthUser = null;
window.jaAuthStateReady = false;

let resolveJaAuthReady = null;

window.jaAuthReady = new Promise(function (resolve) {
  resolveJaAuthReady = resolve;
});


function publishJaAuthState(user) {
  window.jaAuthUser = user || null;

  if (!window.jaAuthStateReady) {
    window.jaAuthStateReady = true;

    if (resolveJaAuthReady) {
      resolveJaAuthReady(window.jaAuthUser);
      resolveJaAuthReady = null;
    }
  }

  window.dispatchEvent(new CustomEvent("ja-auth-state-changed", {
    detail: { user: window.jaAuthUser }
  }));
}


// ================= ACCOUNT BUTTON =================

const accountButton =
  document.getElementById("accountOpenBtn");

const defaultAccountIcon = `
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="8" r="4"/>
    <path d="M5 21a7 7 0 0 1 14 0"/>
  </svg>
`;


function updateAccountButton(user) {
  if (!accountButton) return;

  if (user && user.email) {
    const initial =
      String(user.email).trim().charAt(0).toUpperCase() || "?";

    accountButton.classList.add("is-logged-in");

    accountButton.innerHTML =
      '<span class="account-user-initial" aria-hidden="true">' +
      initial +
      '</span>';

    accountButton.title =
      'Logged in as "' + user.email + '"';

    accountButton.setAttribute(
      "aria-label",
      'Logged in as "' + user.email + '"'
    );

    accountButton.setAttribute(
      "data-user-email",
      user.email
    );

  } else {

    accountButton.classList.remove("is-logged-in");
    accountButton.innerHTML = defaultAccountIcon;
    accountButton.title = "Account";
    accountButton.setAttribute("aria-label", "Open account");
    accountButton.removeAttribute("data-user-email");

  }
}


// ================= COPY / EXPORT ACCESS =================

/* Require an authenticated Firebase session for shared
   Copy / Export controls. Protected datasets are additionally
   enforced by their server-side API. */

function syncCopyExportAccess(user) {
  const locked = !user;

  document.querySelectorAll(".copy-export-control").forEach(control => {

    control.classList.toggle("ja-auth-locked", locked);

    if (locked) {
      const menu = control.querySelector(".copy-export-menu");
      const trigger = control.querySelector(".copy-export-trigger");

      if (menu) menu.hidden = true;

      if (trigger) {
        trigger.setAttribute("aria-expanded", "false");
      }
    }

  });
}


/* Capture phase runs before existing menu and export handlers. */

document.addEventListener("click", function (event) {

  if (window.firebaseAuth && window.firebaseAuth.currentUser) {
    return;
  }

  const control = event.target && event.target.closest
    ? event.target.closest(".copy-export-control")
    : null;

  if (!control) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  const accountButton =
    document.getElementById("accountOpenBtn");

  if (accountButton) accountButton.click();

}, true);


// Observe dynamically created Copy / Export controls.

const copyExportObserver = new MutationObserver(() => {
  syncCopyExportAccess(window.jaAuthUser || null);
});

copyExportObserver.observe(document.documentElement, {
  childList: true,
  subtree: true
});


// ================= CLOUDFLARE GATEWAY SESSION =================

// Firebase remains the identity provider.
// Cloudflare independently validates the ID token,
// email verification and Google Sheets allowlist.
//
// After successful validation, the Worker issues an
// HttpOnly signed session cookie.
//
// No Firebase bearer token is stored in localStorage by us.

let jaSessionSyncPromise = null;


window.jaEnsureCloudflareSession = function (user) {

  if (!user) {
    return Promise.reject(
      new Error("Please sign in to access Jupiter Astro.")
    );
  }

  // Prevent simultaneous session exchanges.
  if (jaSessionSyncPromise) {
    return jaSessionSyncPromise;
  }

  jaSessionSyncPromise = (async function () {

    // Refresh Firebase profile before checking emailVerified.
    await reload(user);

    if (!user.emailVerified) {
      throw new Error(
        "Please verify your email address before accessing Jupiter Astro."
      );
    }

    // Force a fresh Firebase ID token after profile refresh.
     const idToken = await user.getIdToken();
     
    // Exchange Firebase ID token for Cloudflare session.
    const response = await fetch("/__auth/session", {
      method: "POST",
      credentials: "same-origin",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        idToken: idToken
      })
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok || result.success !== true) {
      throw new Error(
        result.error ||
        "Could not establish a secure website session."
      );
    }

    // Notify the application that the Cloudflare session is ready.
    window.dispatchEvent(
      new CustomEvent("ja-cloudflare-session-ready", {
        detail: {
          email: user.email
        }
      })
    );

    return result;

  })().finally(function () {

    jaSessionSyncPromise = null;

  });

  return jaSessionSyncPromise;
};


// ================= CLEAR CLOUDFLARE SESSION =================

async function jaClearCloudflareSession() {

  try {

    await fetch("/__auth/logout", {
      method: "POST",
      credentials: "same-origin",

      headers: {
        "Content-Type": "application/json"
      }
    });

  } catch (error) {

    console.warn(
      "Jupiter Astro: Cloudflare session cleanup could not reach the Worker.",
      error
    );

  }

}


// ================= FIREBASE AUTH STATE LISTENER =================

onIdTokenChanged(auth, async function (user) {

  if (user) {

    try {

      // Refresh Firebase profile, check email verification,
      // and establish the Cloudflare session.
      await window.jaEnsureCloudflareSession(user);

    } catch (sessionError) {

      console.error(
        "Jupiter Astro: Cloudflare session establishment failed.",
        sessionError
      );

      // Do not retain an earlier Cloudflare session.
      await jaClearCloudflareSession();

      publishJaAuthState(null);
      updateAccountButton(null);
      syncCopyExportAccess(null);

      return;
    }

  } else {

    // Firebase user signed out.
    await jaClearCloudflareSession();

  }

  // Publish authenticated state only after successful
  // Cloudflare session establishment.
  publishJaAuthState(user);

  updateAccountButton(user);
  syncCopyExportAccess(user);

}, function (error) {

  console.error(
    "Jupiter Astro: Firebase auth-state listener failed.",
    error
  );

  publishJaAuthState(null);
  updateAccountButton(null);
  syncCopyExportAccess(null);

});


// ================= INITIALIZATION COMPLETE =================

console.log("Jupiter Astro: Firebase initialized successfully.");
