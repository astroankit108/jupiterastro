/**
 * Jupiter Astro — Cloudflare Worker authentication gateway.
 *
 * All requests pass through this Worker before static assets are served.
 * Firebase remains the identity provider; the Worker independently checks
 * Firebase email verification and the existing Google Sheets allowlist.
 */

const LOGIN_ASSETS = new Set([
  "/login.html",
  "/Firebase.js",
  "/Account.js",
  "/Email Verification.js",
  "/css/main67g120kS63cY438.css"
]);

const FIREBASE_LOOKUP_URL =
  "https://identitytoolkit.googleapis.com/v1/accounts:lookup";
const AUTH_CHECK_URL =
  "https://script.google.com/macros/s/AKfycbx02wG3xKMKegEYNYMI-pQbmXhnPiielVJbYtPIXs0waU7150qys4Y1psaulXX1U4qx/exec";
const FIREBASE_API_KEY_FALLBACK = "AIzaSyDwXS6894YgdyuD9-3ThCwsDiSHkyuNFpU";
const SESSION_COOKIE = "ja_session";
const SESSION_TTL_SECONDS = 60 * 60; // One hour; Firebase refresh renews it.

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hmacKey(secret) {
  if (!secret || secret.length < 32) {
    throw new Error("JA_SESSION_HMAC_SECRET must be at least 32 characters.");
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
    if (!payload || !payload.uid || !payload.email ||
        !Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch (_) {
    return null;
  }
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return "";
}

function cookieAttributes(request, maxAge) {
  const host = new URL(request.url).hostname.toLowerCase();
  const domain = host === "jupiterastro.in" || host.endsWith(".jupiterastro.in")
    ? "; Domain=.jupiterastro.in"
    : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}${domain}`;
}

function sessionCookie(request, value, maxAge) {
  const host = new URL(request.url).hostname.toLowerCase();
  const domain = host === "jupiterastro.in" || host.endsWith(".jupiterastro.in")
    ? "; Domain=.jupiterastro.in"
    : "";
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}${domain}`;
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

async function exchangeFirebaseToken(request, env) {
  const body = await request.json().catch(() => null);
  const idToken = body && typeof body.idToken === "string" ? body.idToken : "";
  if (!idToken || idToken.length > 10000) {
    return json({ success: false, error: "A valid Firebase login token is required." }, 401);
  }

  const apiKey = String(env.FIREBASE_WEB_API_KEY || FIREBASE_API_KEY_FALLBACK).trim();
  let lookupResponse;
  try {
    lookupResponse = await fetch(
      FIREBASE_LOOKUP_URL + "?key=" + encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ idToken }),
        signal: AbortSignal.timeout(12000)
      }
    );
  } catch (_) {
    return json({ success: false, error: "Could not validate your Firebase session. Please try again." }, 503);
  }

  const lookup = await lookupResponse.json().catch(() => ({}));
  const user = Array.isArray(lookup.users) && lookup.users[0];
  if (!lookupResponse.ok || !user || !user.localId || !user.email) {
    return json({ success: false, error: "Your login has expired. Please sign in again." }, 401);
  }
  if (user.emailVerified !== true) {
    return json({ success: false, error: "Please verify your email address before accessing Jupiter Astro." }, 403);
  }

  let authorized = false;
  try {
    authorized = await verifyAuthorizedEmail(String(user.email).trim().toLowerCase());
  } catch (error) {
    return json({ success: false, error: error.message || "Could not verify your access." }, 503);
  }
  if (!authorized) {
    return json({
      success: false,
      error: "This email address is not authorized. Please contact consult@jupiterastrology108.com."
    }, 403);
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    uid: user.localId,
    email: String(user.email).trim().toLowerCase(),
    iat: now,
    exp: now + SESSION_TTL_SECONDS
  };

  let token;
  try {
    token = await createSession(payload, env.JA_SESSION_HMAC_SECRET);
  } catch (error) {
    return json({ success: false, error: "The secure login service is not configured correctly." }, 503);
  }

  return json(
    { success: true, email: payload.email, expiresAt: payload.exp },
    200,
    { "Set-Cookie": sessionCookie(request, token, SESSION_TTL_SECONDS) }
  );
}

async function serveLogin(request, env) {
  const assetUrl = new URL("/login.html", request.url);
  const assetRequest = new Request(assetUrl.toString(), {
    method: "GET",
    headers: request.headers
  });
  const response = await env.ASSETS.fetch(assetRequest);
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  return new Response(response.body, { status: response.status, headers });
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
    const path = decodeURIComponent(url.pathname);

    if (request.method === "POST" && path === "/__auth/session") {
      const origin = request.headers.get("Origin");
      if (origin && new URL(origin).host !== url.host) {
        return json({ success: false, error: "Invalid request origin." }, 403);
      }
      return exchangeFirebaseToken(request, env);
    }

    if (request.method === "POST" && path === "/__auth/logout") {
      return json(
        { success: true },
        200,
        { "Set-Cookie": cookieAttributes(request, 0) }
      );
    }

    const session = await readSession(
      getCookie(request, SESSION_COOKIE),
      env.JA_SESSION_HMAC_SECRET
    );

    if (path === "/login.html" && session) {
      return Response.redirect(new URL("/", request.url), 302);
    }

    if (!session) {
      const safeRead = request.method === "GET" || request.method === "HEAD";
      if (safeRead && (path === "/" || path === "/index.html" || path === "/login.html" || isDocumentRequest(request))) {
        return serveLogin(request, env);
      }

      if (safeRead && LOGIN_ASSETS.has(path)) {
        return protectedAsset(request, env);
      }

      return json({ error: "Authentication required. Please sign in." }, 401);
    }

    if (path === "/login.html") {
      return Response.redirect(new URL("/", request.url), 302);
    }

    return protectedAsset(request, env);
  }
};
