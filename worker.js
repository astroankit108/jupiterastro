/**
 * Jupiter Astro — Cloudflare authentication gateway.
 *
 * Flow: Firebase ID token -> Identity Toolkit accounts:lookup ->
 * verified email -> Google Sheets allowlist -> signed HttpOnly cookie.
 *
 * Required Worker secrets:
 *   FIREBASE_WEB_API_KEY  A server-use Firebase Web API key with the
 *                         Identity Toolkit API enabled. Do not use a
 *                         browser-referrer-restricted key.
 *   JA_SESSION_HMAC_SECRET  Random secret, at least 32 characters.
 */

const LOGIN_ASSETS = new Set([
  "/login.html",
  "/Firebase.js",
  "/Account.js",
  "/Email Verification.js",
  "/css/main67g120kS63cY438.css",
  "/favicon.ico"
]);

const FIREBASE_PROJECT_ID = "jupiter-astro";
const FIREBASE_LOOKUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup";
const AUTH_CHECK_URL = "https://script.google.com/macros/s/AKfycbx02wG3xKMKegEYNYMI-pQbmXhnPiielVJbYtPIXs0waU7150qys4Y1psaulXX1U4qx/exec";
const SESSION_COOKIE = "ja_session";
const SESSION_TTL_SECONDS = 60 * 60;
const MAX_ID_TOKEN_LENGTH = 10000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "Pragma": "no-cache",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function failure(code, error, status, requestId) {
  return json({ success: false, code, error, requestId }, status);
}

function requestId() {
  return crypto.randomUUID();
}

function base64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function hmacKey(secret) {
  if (typeof secret !== "string" || secret.trim().length < 32) {
    throw new Error("JA_SESSION_HMAC_SECRET must contain at least 32 characters.");
  }
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createSession(payload, secret) {
  const encoded = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await hmacKey(secret);
  const signature = new Uint8Array(await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(encoded)
  ));
  return encoded + "." + base64url(signature);
}

async function readSession(token, secret) {
  if (!token || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC", key, fromBase64url(parts[1]), new TextEncoder().encode(parts[0])
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    const now = Math.floor(Date.now() / 1000);
    if (
      !payload || payload.iss !== "jupiterastro" ||
      payload.aud !== "jupiterastro.in" ||
      typeof payload.uid !== "string" || !payload.uid ||
      typeof payload.email !== "string" || !payload.email.includes("@") ||
      !Number.isFinite(payload.exp) || payload.exp <= now ||
      !Number.isFinite(payload.iat) || payload.iat > now + 60
    ) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return "";
}

// Host-only cookie: no Domain attribute, so sibling subdomains cannot share it.
function sessionCookie(value, maxAge) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function expiredSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function validateSameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === url.origin;
  } catch (_) {
    return false;
  }
}

// Read only the untrusted JWT payload for an early project-mismatch check.
// This does NOT authenticate the token; accounts:lookup below remains the
// authoritative Google-side validation step.
function decodeUntrustedJwtPayload(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const bytes = fromBase64url(parts[1]);
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (_) {
    return null;
  }
}

function parseAuthorizationResult(raw) {
  const text = String(raw || "").trim();
  try { return JSON.parse(text); } catch (_) {}
  const match = text.match(/^[\w.$]+\s*\(([\s\S]*)\)\s*;?$/);
  if (match) {
    try { return JSON.parse(match[1]); } catch (_) {}
  }
  throw new Error("The email authorization service returned an unreadable response.");
}

async function verifyAuthorizedEmail(email) {
  const url = new URL(AUTH_CHECK_URL);
  url.searchParams.set("action", "verifyEmail");
  url.searchParams.set("email", email);
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { "Accept": "application/json, text/javascript" },
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error("The email authorization service is unavailable.");
  const result = parseAuthorizationResult(await response.text());
  if (!result || result.success !== true || typeof result.authorized !== "boolean") {
    throw new Error("The email authorization service did not confirm access.");
  }
  return result.authorized;
}

async function exchangeFirebaseToken(request, env, id) {
  let body;
  try { body = await request.json(); }
  catch (_) { return failure("INVALID_REQUEST", "The login request was not valid JSON.", 400, id); }

  const idToken = typeof body?.idToken === "string" ? body.idToken.trim() : "";
  if (!idToken || idToken.length > MAX_ID_TOKEN_LENGTH) {
    return failure("FIREBASE_TOKEN_MISSING", "Firebase did not provide a valid sign-in token. Please sign in again.", 401, id);
  }

  const tokenClaims = decodeUntrustedJwtPayload(idToken);
  if (!tokenClaims || tokenClaims.aud !== FIREBASE_PROJECT_ID ||
      tokenClaims.iss !== "https://securetoken.google.com/" + FIREBASE_PROJECT_ID) {
    console.error("JA_FIREBASE_PROJECT_MISMATCH", {
      requestId: id,
      tokenAudience: typeof tokenClaims?.aud === "string" ? tokenClaims.aud : null,
      tokenIssuer: typeof tokenClaims?.iss === "string" ? tokenClaims.iss : null
    });
    return failure("FIREBASE_PROJECT_MISMATCH", "This sign-in belongs to a different Firebase project. Please contact the website administrator.", 401, id);
  }

  const apiKey = String(env.FIREBASE_WEB_API_KEY || "").trim();
  if (!apiKey) {
    console.error("JA_AUTH_CONFIG_ERROR", { requestId: id, code: "FIREBASE_WEB_API_KEY_MISSING" });
    return failure("FIREBASE_API_KEY_NOT_CONFIGURED", "The secure login service is not fully configured. Please contact the website administrator.", 503, id);
  }

  try { await hmacKey(env.JA_SESSION_HMAC_SECRET); }
  catch (error) {
    console.error("JA_AUTH_CONFIG_ERROR", { requestId: id, code: "SESSION_SECRET_INVALID", message: error.message });
    return failure("SESSION_SECRET_NOT_CONFIGURED", "The secure login service is not fully configured. Please contact the website administrator.", 503, id);
  }

  let lookupResponse;
  try {
    lookupResponse = await fetch(FIREBASE_LOOKUP_URL + "?key=" + encodeURIComponent(apiKey), {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ idToken }),
      signal: AbortSignal.timeout(12000)
    });
  } catch (error) {
    console.error("JA_FIREBASE_LOOKUP_NETWORK_ERROR", { requestId: id, name: error?.name || "Error" });
    return failure("FIREBASE_LOOKUP_UNAVAILABLE", "The identity verification service is temporarily unavailable. Please try again.", 503, id);
  }

  let lookup = {};
  try { lookup = await lookupResponse.json(); }
  catch (_) {
    console.error("JA_FIREBASE_LOOKUP_BAD_RESPONSE", { requestId: id, status: lookupResponse.status });
    return failure("FIREBASE_LOOKUP_BAD_RESPONSE", "The identity verification service returned an invalid response.", 502, id);
  }

  const user = Array.isArray(lookup?.users) ? lookup.users[0] : null;
  if (!lookupResponse.ok || !user?.localId || !user?.email) {
    const firebaseError = String(lookup?.error?.message || "UNKNOWN_FIREBASE_ERROR");
    const keyProblem = /API_KEY_INVALID|API_KEY_HTTP_REFERRER_BLOCKED|API_KEY_IP_ADDRESS_BLOCKED|API_KEY_SERVICE_BLOCKED|PROJECT_NOT_FOUND/.test(firebaseError);
    console.error("JA_FIREBASE_TOKEN_VALIDATION_FAILED", {
      requestId: id,
      httpStatus: lookupResponse.status,
      firebaseError,
      hasUsers: Array.isArray(lookup?.users),
      hasLocalId: Boolean(user?.localId),
      hasEmail: Boolean(user?.email)
    });
    if (keyProblem) {
      return failure("FIREBASE_API_KEY_REJECTED", "The website's Firebase server API key is restricted or incorrect. Please contact the website administrator.", 503, id);
    }
    return failure("FIREBASE_TOKEN_REJECTED", "Firebase could not validate this sign-in. Please sign in again.", 401, id);
  }

  if (user.emailVerified !== true) {
    return failure("EMAIL_NOT_VERIFIED", "Please verify your email address before accessing Jupiter Astro.", 403, id);
  }

  const email = String(user.email).trim().toLowerCase();
  let authorized;
  try {
    authorized = await verifyAuthorizedEmail(email);
  } catch (error) {
    console.error("JA_EMAIL_AUTHORIZATION_SERVICE_ERROR", { requestId: id, message: error?.message || "Unknown error" });
    return failure("EMAIL_AUTHORIZATION_UNAVAILABLE", "Could not verify your website access right now. Please try again.", 503, id);
  }
  if (!authorized) {
    return failure("EMAIL_NOT_AUTHORIZED", "This email address is not authorized. Please contact consult@jupiterastrology108.com.", 403, id);
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "jupiterastro",
    aud: "jupiterastro.in",
    ver: 1,
    uid: user.localId,
    email,
    iat: now,
    exp: now + SESSION_TTL_SECONDS
  };

  let signedSession;
  try { signedSession = await createSession(payload, env.JA_SESSION_HMAC_SECRET); }
  catch (error) {
    console.error("JA_SESSION_SIGNING_FAILED", { requestId: id, message: error?.message || "Unknown error" });
    return failure("SESSION_CREATION_FAILED", "The secure website session could not be created. Please try again.", 503, id);
  }

  console.info("JA_AUTH_SESSION_CREATED", { requestId: id, projectId: FIREBASE_PROJECT_ID });
  return json(
    { success: true, email, expiresAt: payload.exp, requestId: id },
    200,
    { "Set-Cookie": sessionCookie(signedSession, SESSION_TTL_SECONDS) }
  );
}

async function serveLogin(request, env) {
  const assetUrl = new URL("/login.html", request.url);
  const assetRequest = new Request(assetUrl.toString(), { method: "GET", headers: request.headers });
  const response = await env.ASSETS.fetch(assetRequest);
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function isDocumentRequest(request) {
  return (request.headers.get("Accept") || "").includes("text/html");
}

async function protectedAsset(request, env) {
  const response = await env.ASSETS.fetch(request);
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store, max-age=0");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path;
    try { path = decodeURIComponent(url.pathname); }
    catch (_) { return json({ error: "Invalid URL path." }, 400); }

    if (request.method === "POST" && path === "/__auth/session") {
      if (!validateSameOrigin(request, url)) {
        return failure("INVALID_ORIGIN", "Invalid request origin.", 403, requestId());
      }
      return exchangeFirebaseToken(request, env, requestId());
    }

    if (request.method === "POST" && path === "/__auth/logout") {
      if (!validateSameOrigin(request, url)) {
        return failure("INVALID_ORIGIN", "Invalid request origin.", 403, requestId());
      }
      return json({ success: true }, 200, { "Set-Cookie": expiredSessionCookie() });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { "Allow": "GET, HEAD, POST, OPTIONS" } });
    }

    const session = await readSession(getCookie(request, SESSION_COOKIE), env.JA_SESSION_HMAC_SECRET);

    if (path === "/login.html" && session) {
      return Response.redirect(new URL("/", request.url), 302);
    }

    if (!session) {
      const safeRead = request.method === "GET" || request.method === "HEAD";
      if (safeRead && (path === "/" || path === "/index.html" || path === "/login.html" || isDocumentRequest(request))) {
        return serveLogin(request, env);
      }
      if (safeRead && LOGIN_ASSETS.has(path)) return protectedAsset(request, env);
      return json({ success: false, code: "AUTHENTICATION_REQUIRED", error: "Authentication required. Please sign in." }, 401);
    }

    if (path === "/login.html") return Response.redirect(new URL("/", request.url), 302);
    return protectedAsset(request, env);
  }
};
