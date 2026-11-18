Jupiter Astro — Cloudflare Worker authentication gateway
This project is configured for the existing Cloudflare Worker named `jupiterastro`.
It is not a Cloudflare Pages or Vercel deployment.
What this change does
Runs the Worker before every static asset request (`assets.run_worker_first = true`).
Serves only the existing Jupiter Astro Sign In / Set Password dialogue to visitors without a valid Worker session.
Exchanges a Firebase ID token for a signed, HttpOnly, Secure session cookie.
Independently checks Firebase email verification and the existing Google Apps Script / Google Sheets email authorization endpoint.
Protects the static application files, including JavaScript, CSS, JSON datasets and `/api/*` paths, behind the same cookie check.
Applies to both custom domains and the `workers.dev` hostname because all three are attached to this Worker.
Uses a one-hour Worker cookie. Firebase's `onIdTokenChanged` listener renews it as Firebase refreshes the ID token.
Before deploying
Keep the existing Cloudflare Worker name `jupiterastro`.
Keep the current GitHub repository `astroankit108/jupiterastro`, production branch `main`, root directory `/`, build command `None`, and deploy command `npx wrangler deploy`.
In Cloudflare Dashboard → Workers & Pages → `jupiterastro` → Settings → Variables and Secrets, add:
Type: Secret
Name: `JA_SESSION_HMAC_SECRET`
Value: a newly generated random value of at least 32 characters. Generate one with `openssl rand -hex 32`.
Do not remove the existing Google Drive service-account secrets or other Worker variables. `keep_vars = true` is included to retain dashboard-managed plain variables; Wrangler also preserves existing encrypted secrets on deploy.
Commit the changed files to the existing `main` branch. Cloudflare's existing Git integration will run `npx wrangler deploy`.
Files changed
`worker.js` — authentication gateway and static asset gate.
`wrangler.toml` — attaches the existing static asset directory to the Worker and runs the Worker before every asset.
`.assetsignore` — prevents Worker source and deployment configuration from being served as public static files.
`login.html` — login-only shell extracted from the existing account dialogue markup and styled with the existing main stylesheet.
`Firebase.js` — exchanges verified Firebase sessions for the Worker cookie and renews it when Firebase ID tokens refresh.
`Account.js` — waits for Cloudflare session establishment after Sign In and clears the Worker cookie on Logout.
Important security behaviour
`jupiterastro.in`, `research.jupiterastro.in`, and `jupiterastro.consult-9cb.workers.dev` all use the same Worker gate.
The session cookie is host-only on `workers.dev` and shared across `.jupiterastro.in` on the custom domains.
Unauthenticated document requests receive `login.html`; non-login asset/API requests receive HTTP 401.
A signed cookie is not a Firebase ID token. The Worker creates it only after validating the ID token with Firebase and checking the Google Sheets authorization endpoint.
Email authorization is checked when the cookie is issued or renewed. A change to the allowlist can take up to the one-hour cookie lifetime to take effect for an already-issued session.
Logout clears the cookie. If a browser's Firebase state is still signed in, the existing login page can establish a new Worker session after a subsequent authenticated sign-in/reload; normal logout signs Firebase out as well.
Deploy and test safely
After the first deployment, test in a private/incognito window:
Open `https://jupiterastro.in/` — only the login dialogue should appear.
Open `https://research.jupiterastro.in/` — only the login dialogue should appear.
Open `https://jupiterastro.consult-9cb.workers.dev/` — only the login dialogue should appear.
Try `/index.html`, `/Firebase.js`, a protected JSON file, and an `/api/...` URL while signed out. Only the three login scripts and login stylesheet should be available; protected paths should return HTTP 401 (HTML navigations show the login dialogue).
Sign in using an authorized, email-verified account. The Worker should issue the cookie and redirect to the full application.
Open both custom domains in the same browser. The `.jupiterastro.in` cookie should work across them.
Log out. Refresh and directly request a protected JSON or JavaScript file; access should be denied.
Important scope note
The uploaded project contains API handler files under `/api`, but the supplied Cloudflare dashboard screenshots show a static-assets-only Worker and no executable API routing. This change gates those paths; it does not convert each existing API handler into a running Worker route. API execution should be handled as a separate migration if those endpoints are intended to run on this Worker.
