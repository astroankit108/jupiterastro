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
  // Restrict this API key by HTTP referrer and enabled APIs in Google Cloud.
  window.jaFirebaseConfig = {
    apiKey: firebaseConfig.apiKey,
    // Defaults to the Firebase key. You may replace this with a dedicated
    // Google Drive API key restricted to your website's HTTP referrers.
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

  window.dispatchEvent(new CustomEvent('ja-auth-state-changed', {
    detail: { user: window.jaAuthUser }
  }));
}

const accountButton =
  document.getElementById('accountOpenBtn');

const defaultAccountIcon = `
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="8" r="4"/>
    <path d="M5 21a7 7 0 0 1 14 0"/>
  </svg>
`;

function updateAccountButton(user) {
  if (!accountButton) return;

  if (user && user.email) {
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

/* Require an authenticated Firebase session for all shared Copy / Export
   controls. The protected Dasha dataset is additionally enforced by its API. */
function syncCopyExportAccess(user) {
  const locked = !user;
  document.querySelectorAll(".copy-export-control").forEach(control => {
    control.classList.toggle("ja-auth-locked", locked);
    if (locked) {
      const menu = control.querySelector(".copy-export-menu");
      const trigger = control.querySelector(".copy-export-trigger");
      if (menu) menu.hidden = true;
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    }
  });
}

/* Capture phase runs before the page's existing menu and export handlers. */
document.addEventListener("click", function (event) {
  if (window.firebaseAuth && window.firebaseAuth.currentUser) return;
  const control = event.target && event.target.closest
    ? event.target.closest(".copy-export-control")
    : null;
  if (!control) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  const accountButton = document.getElementById("accountOpenBtn");
  if (accountButton) accountButton.click();
}, true);

const copyExportObserver = new MutationObserver(() => {
  syncCopyExportAccess(window.jaAuthUser || null);
});
copyExportObserver.observe(document.documentElement, {
  childList: true,
  subtree: true
});


// ================= CLOUDFLARE GATEWAY SESSION =================
// Firebase remains the identity provider. The Worker validates the ID token,
// checks email verification + the Google Sheets allowlist, then issues an
// HttpOnly signed cookie. No bearer token is stored in localStorage by us.
let jaSessionSyncPromise = null;
window.jaEnsureCloudflareSession = function (user) {
  if (!user || !user.emailVerified) {
    return Promise.reject(new Error("Please verify your email address before accessing Jupiter Astro."));
  }
  if (jaSessionSyncPromise) return jaSessionSyncPromise;

  jaSessionSyncPromise = (async function () {
    const idToken = await user.getIdToken();
    const response = await fetch("/__auth/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.success !== true) {
      throw new Error(result.error || "Could not establish a secure website session.");
    }
    window.dispatchEvent(new CustomEvent("ja-cloudflare-session-ready", {
      detail: { email: user.email }
    }));
    return result;
  })().finally(function () {
    jaSessionSyncPromise = null;
  });
  return jaSessionSyncPromise;
};

async function jaClearCloudflareSession() {
  try {
    await fetch("/__auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.warn("Jupiter Astro: Cloudflare session cleanup could not reach the Worker.", error);
  }
}

onIdTokenChanged(auth, async function(user) {

  // A verified Firebase user must also obtain the Worker-issued HttpOnly
  // session before protected application assets can be served.
  if (user && user.emailVerified) {
    try {
      await window.jaEnsureCloudflareSession(user);
    } catch (sessionError) {
      console.error("Jupiter Astro: Cloudflare session establishment failed.", sessionError);
      publishJaAuthState(null);
      return;
    }
  } else {
    // A signed-in but unverified account must never retain a previous user's
    // Worker cookie.
    await jaClearCloudflareSession();
  }

  // Publish the current login state and notify gated features.
  publishJaAuthState(user);

  // Update account identity and apply the global copy/export access gate.
  updateAccountButton(user);
  syncCopyExportAccess(user);

}, function (error) {
  console.error("Jupiter Astro: Firebase auth-state listener failed.", error);
  publishJaAuthState(null);
});

  console.log("Jupiter Astro: Firebase initialized successfully.");
