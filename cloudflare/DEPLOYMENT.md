# Jupiter Astro authentication redesign — deployment

## Files in this package

Replace these files in the Cloudflare static-assets project:

- `Firebase.js`
- `Account.js`
- `Email Verification.js` (retained unchanged; included for a matched file set)
- `worker.js`
- `login.html` (retained unchanged; included for a matched file set)
- `wrangler.toml`

The account UI and Google Sheets allowlist flow are retained. The main changes are a single coordinated Firebase/Cloudflare session exchange, forced ID-token refresh, single logout cleanup, explicit Worker error codes, and login/logout activity events.

## Required Cloudflare secrets

The Worker now requires two secrets:

1. `FIREBASE_WEB_API_KEY`
2. `JA_SESSION_HMAC_SECRET`

`FIREBASE_WEB_API_KEY` is the Firebase **Web API key**, not a Firebase ID token. Do not paste a user's ID token into Cloudflare secrets. ID tokens are generated at sign-in and sent to `/__auth/session` automatically.

For `FIREBASE_WEB_API_KEY`, use a key belonging to the `jupiter-astro` Firebase project. Because the Worker calls Google's Identity Toolkit API server-to-server, do not use an HTTP-referrer-restricted browser key. Create/use a dedicated key with application restrictions set to `None` and API restrictions limited to the Identity Toolkit API (where available). Keep it in Cloudflare as a Secret rather than putting it in source control.

Set the secret in Cloudflare Dashboard:

Workers & Pages → `jupiterastro` → Settings → Variables and Secrets → Add → Secret.

Or with Wrangler:

```bash
npx wrangler secret put FIREBASE_WEB_API_KEY
npx wrangler secret put JA_SESSION_HMAC_SECRET
```

For `JA_SESSION_HMAC_SECRET`, use a cryptographically random value of at least 32 characters. Do not reuse the Firebase API key as the HMAC secret.

## Deployment order

1. Add/verify both Worker secrets first.
2. Deploy the static assets and Worker together from the same project directory.
3. Confirm the Worker is attached to `jupiterastro.in` and routes requests before static assets.
4. Open `/login.html`, authorize an email, and sign in.
5. In Worker logs, a successful login produces `JA_AUTH_SESSION_CREATED`. Failures produce a specific `code` and a request ID; tokens and passwords are never logged.

## Security notes

- Keep the browser email authorization check for user experience, but the Worker independently checks the Google Sheets allowlist before issuing a session.
- Keep Firebase email verification enabled.
- Do not remove the Worker allowlist check or the HMAC session signature.
- Login/logout activity logging from the browser is best-effort audit logging, not a security control. Never log passwords, Firebase ID tokens, reset links, or session cookies.
- The Worker now uses a host-only `ja_session` cookie. Existing domain-scoped cookies may remain in a browser until they expire; sign out once after deployment or clear old `ja_session` cookies for `jupiterastro.in` if a stale cookie interferes.
