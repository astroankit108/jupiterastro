/**
 * JupiterAstro Google Drive API — Cloudflare Workers adapter
 *
 * Replaces the Vercel-style api/drive.js handler.
 * Import handleDriveRequest() from your existing Worker entry point and
 * route /api/drive requests to it.
 *
 * Required Worker secrets/variables:
 *   GOOGLE_DRIVE_SERVICE_ACCOUNT_EMAIL
 *   GOOGLE_DRIVE_SERVICE_ACCOUNT_PRIVATE_KEY  (Secret)
 *   FIREBASE_WEB_API_KEY                     (Variable; optional if using the
 *                                              existing public fallback below)
 *
 * Optional DOCX-to-PDF converter settings:
 *   DOCX_PDF_CONVERTER_URL
 *   DOCX_PDF_CONVERTER_USERNAME
 *   DOCX_PDF_CONVERTER_PASSWORD                (Secret)
 */

"use strict";

const DRIVE_API = "https://www.googleapis.com/drive/v3";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIREBASE_LOOKUP_URL =
  "https://identitytoolkit.googleapis.com/v1/accounts:lookup";
const FIREBASE_API_KEY_FALLBACK = "AIzaSyDwXS689Y4gdyuD9-3ThCwsDiSHkyuNFpU";

const ROOT_FOLDER_ID = "10ZkA2yVR0xHS9qpWpBRLjOKOCWIrzsNj";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly";
const MAX_FOLDER_DEPTH = 30;

const EXPORTS = {
  "application/vnd.google-apps.document": {
    mimeType:
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    extension: ".docx",
  },
  "application/vnd.google-apps.spreadsheet": {
    mimeType:
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    extension: ".xlsx",
  },
  "application/vnd.google-apps.presentation": {
    mimeType:
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    extension: ".pptx",
  },
  "application/vnd.google-apps.drawing": {
    mimeType: "application/pdf",
    extension: ".pdf",
  },
};

// A Worker isolate may be reused between requests. Cache the Google access
// token in memory, but never persist credentials or tokens in browser storage.
let cachedAccessToken = null;
let tokenExpiresAt = 0;
let tokenPromise = null;

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
  }
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function errorResponse(status, message, extraHeaders = {}) {
  return jsonResponse({ error: message }, status, extraHeaders);
}

function getEnvValue(env, key) {
  return String(env && env[key] != null ? env[key] : "").trim();
}

function getGoogleCredentials(env) {
  const email = getEnvValue(env, "GOOGLE_DRIVE_SERVICE_ACCOUNT_EMAIL");
  const privateKey = String(
    env && env.GOOGLE_DRIVE_SERVICE_ACCOUNT_PRIVATE_KEY != null
      ? env.GOOGLE_DRIVE_SERVICE_ACCOUNT_PRIVATE_KEY
      : ""
  )
    .replace(/\\n/g, "\n")
    .trim();

  if (
    !email ||
    !privateKey ||
    !privateKey.includes("-----BEGIN PRIVATE KEY-----")
  ) {
    throw new HttpError(
      503,
      "Google Drive is not configured on this Cloudflare Worker. Add GOOGLE_DRIVE_SERVICE_ACCOUNT_EMAIL and GOOGLE_DRIVE_SERVICE_ACCOUNT_PRIVATE_KEY under Worker Settings → Variables and Secrets, then deploy."
    );
  }

  return { email, privateKey };
}

function bytesToBase64Url(bytes) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function textToBase64Url(value) {
  return bytesToBase64Url(new TextEncoder().encode(value));
}

function pemToArrayBuffer(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  let binary;
  try {
    binary = atob(body);
  } catch {
    throw new HttpError(
      503,
      "The Google service-account private key is not valid PEM data. Copy the private_key value from the service-account JSON file."
    );
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function createGoogleAssertion(credentials) {
  const now = Math.floor(Date.now() / 1000);
  const unsigned =
    textToBase64Url(JSON.stringify({ alg: "RS256", typ: "JWT" })) +
    "." +
    textToBase64Url(
      JSON.stringify({
        iss: credentials.email,
        scope: DRIVE_SCOPE,
        aud: TOKEN_URL,
        iat: now,
        exp: now + 3600,
      })
    );

  let signingKey;
  try {
    signingKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(credentials.privateKey),
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );
  } catch (error) {
    console.error("Could not import Google service-account private key:", error);
    throw new HttpError(
      503,
      "Cloudflare could not read the Google service-account private key. Check that the complete private_key value, including BEGIN/END lines, is stored as a Worker Secret."
    );
  }

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey,
    new TextEncoder().encode(unsigned)
  );

  return unsigned + "." + bytesToBase64Url(new Uint8Array(signature));
}

async function getGoogleAccessToken(env) {
  if (cachedAccessToken && tokenExpiresAt > Date.now() + 60_000) {
    return cachedAccessToken;
  }
  if (tokenPromise) return tokenPromise;

  tokenPromise = (async () => {
    const credentials = getGoogleCredentials(env);
    const assertion = await createGoogleAssertion(credentials);

    let response;
    try {
      response = await fetch(TOKEN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
          assertion,
        }),
      });
    } catch (error) {
      console.error("Google OAuth token request failed:", error);
      throw new HttpError(
        502,
        "Cloudflare could not reach Google's authentication service."
      );
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.access_token) {
      console.error(
        "Drive service-account authentication failed:",
        response.status,
        data.error || ""
      );
      throw new HttpError(
        502,
        "Google could not authenticate the Library service account. Check its email, private key, and Google Drive API access."
      );
    }

    cachedAccessToken = data.access_token;
    tokenExpiresAt =
      Date.now() + Math.max(60, Number(data.expires_in) || 3600) * 1000;
    return cachedAccessToken;
  })();

  try {
    return await tokenPromise;
  } finally {
    tokenPromise = null;
  }
}

async function verifyFirebaseSession(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+([^\s]+)$/i);

  if (!match) {
    throw new HttpError(401, "Please log in to continue.");
  }

  const idToken = match[1];
  if (idToken.length > 10_000) {
    throw new HttpError(
      401,
      "Your login session is invalid. Please log in again."
    );
  }

  const apiKey =
    getEnvValue(env, "FIREBASE_WEB_API_KEY") || FIREBASE_API_KEY_FALLBACK;

  let response;
  try {
    response = await fetch(
      FIREBASE_LOOKUP_URL + "?key=" + encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ idToken }),
        signal: AbortSignal.timeout(12_000),
      }
    );
  } catch (error) {
    console.error("Firebase session lookup failed:", error);
    throw new HttpError(
      503,
      "Could not validate your login session. Please try again."
    );
  }

  const data = await response.json().catch(() => ({}));
  const user = Array.isArray(data.users) && data.users[0];

  if (!response.ok || !user || !user.localId || !user.email) {
    throw new HttpError(
      401,
      "Your login session has expired. Please log in again."
    );
  }

  // Intentionally mirrors the original verifyFirebaseSession() behavior:
  // it verifies that the Firebase session is valid but does not impose
  // emailVerified or the separate Google-Sheets email allowlist check.
  return {
    uid: user.localId,
    email: String(user.email).trim().toLowerCase(),
  };
}

function buildDriveUrl(path, params) {
  const url = new URL(DRIVE_API + path);

  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }

  return url;
}

function resourceKeyHeaders(fileId, resourceKey) {
  return resourceKey
    ? { "X-Goog-Drive-Resource-Keys": fileId + "/" + resourceKey }
    : {};
}

async function getMetadata(fileId, token, resourceKey) {
  const url = buildDriveUrl("/files/" + encodeURIComponent(fileId), {
    supportsAllDrives: "true",
    fields:
      "id,name,mimeType,parents,resourceKey,shortcutDetails(targetId,targetMimeType,targetResourceKey),capabilities(canDownload),size,modifiedTime,webViewLink",
  });

  const response = await fetch(url.toString(), {
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/json",
      ...resourceKeyHeaders(fileId, resourceKey),
    },
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new HttpError(
      response.status,
      (body.error && body.error.message) ||
        "Google Drive metadata request failed."
    );
  }

  return body;
}

async function assertInsideLibrary(fileId, token, resourceKey) {
  let currentId = fileId;
  let currentKey = resourceKey || "";
  const visited = new Set();

  for (let depth = 0; depth < MAX_FOLDER_DEPTH; depth += 1) {
    if (currentId === ROOT_FOLDER_ID) return true;
    if (visited.has(currentId)) return false;
    visited.add(currentId);

    const metadata = await getMetadata(currentId, token, currentKey);
    const parents = Array.isArray(metadata.parents) ? metadata.parents : [];

    if (parents.includes(ROOT_FOLDER_ID)) return true;
    if (!parents.length) return false;

    currentId = parents[0];
    currentKey = "";
  }

  return false;
}

function safeFilename(value) {
  return (
    String(value || "drive-file")
      .replace(/[\r\n"\\/]/g, "_")
      .slice(0, 180) || "drive-file"
  );
}

async function listFolder(urlParams, token) {
  const folderId = String(urlParams.get("folderId") || ROOT_FOLDER_ID).trim();
  const pageToken = String(urlParams.get("pageToken") || "").trim();

  if (!/^[A-Za-z0-9_-]{10,200}$/.test(folderId)) {
    throw new HttpError(400, "Invalid Library folder identifier.");
  }
  if (pageToken.length > 4096) {
    throw new HttpError(400, "Invalid Drive page token.");
  }

  if (!(await assertInsideLibrary(folderId, token))) {
    throw new HttpError(
      403,
      "This folder is not inside the configured Jupiter Astrology Library."
    );
  }

  const url = buildDriveUrl("/files", {
    q: "'" + folderId + "' in parents and trashed = false",
    pageSize: 100,
    orderBy: "folder,name",
    supportsAllDrives: "true",
    includeItemsFromAllDrives: "true",
    fields:
      "nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink,thumbnailLink,resourceKey,capabilities(canDownload),shortcutDetails(targetId,targetMimeType,targetResourceKey))",
    pageToken,
  });

  const response = await fetch(url.toString(), {
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/json",
    },
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new HttpError(
      response.status === 403 ? 403 : response.status === 404 ? 404 : 502,
      (data.error && data.error.message) || "Google Drive folder listing failed."
    );
  }

  return jsonResponse(data, 200, {
    "Cache-Control": "private, no-store",
    Vary: "Authorization",
  });
}

async function resolveShortcut(fileId, token, resourceKey) {
  let metadata = await getMetadata(fileId, token, resourceKey);

  if (
    metadata.mimeType === "application/vnd.google-apps.shortcut" &&
    metadata.shortcutDetails &&
    metadata.shortcutDetails.targetId
  ) {
    const shortcut = metadata.shortcutDetails;
    const targetId = shortcut.targetId;
    const targetKey = shortcut.targetResourceKey || "";

    if (!(await assertInsideLibrary(targetId, token, targetKey))) {
      throw new HttpError(
        403,
        "This shortcut points to a file outside the configured Library folder."
      );
    }

    metadata = await getMetadata(targetId, token, targetKey);
  }

  return metadata;
}

async function downloadFile(urlParams, token) {
  const fileId = String(urlParams.get("fileId") || "").trim();
  const resourceKey = String(urlParams.get("resourceKey") || "").trim();

  if (!/^[A-Za-z0-9_-]{10,200}$/.test(fileId)) {
    throw new HttpError(400, "Invalid Google Drive file identifier.");
  }

  if (!(await assertInsideLibrary(fileId, token, resourceKey))) {
    throw new HttpError(
      403,
      "This file is not inside the configured Jupiter Astrology Library folder."
    );
  }

  const metadata = await resolveShortcut(fileId, token, resourceKey);

  if (metadata.capabilities && metadata.capabilities.canDownload === false) {
    throw new HttpError(
      403,
      "The file owner has disabled downloading. Open this item in Google Drive instead."
    );
  }

  const exportInfo = EXPORTS[metadata.mimeType] || null;
  const url = exportInfo
    ? buildDriveUrl(
        "/files/" + encodeURIComponent(metadata.id) + "/export",
        { mimeType: exportInfo.mimeType }
      )
    : buildDriveUrl("/files/" + encodeURIComponent(metadata.id), {
        alt: "media",
        supportsAllDrives: "true",
      });

  const headers = { Authorization: "Bearer " + token };
  if (metadata.resourceKey) {
    headers["X-Goog-Drive-Resource-Keys"] =
      metadata.id + "/" + metadata.resourceKey;
  }

  const upstream = await fetch(url.toString(), {
    method: "GET",
    headers,
  });

  if (!upstream.ok) {
    const body = await upstream.json().catch(() => ({}));
    const message =
      (body.error && body.error.message) ||
      "Google Drive could not return this file.";

    if (exportInfo && /10.?MB|export.*size|file.*too large/i.test(message)) {
      throw new HttpError(
        413,
        "Google Drive limits native Docs, Sheets and Slides exports to 10 MB. Open this file in Google Drive instead."
      );
    }

    console.error(
      "Drive file content request failed:",
      upstream.status,
      message
    );

    throw new HttpError(
      upstream.status === 403
        ? 403
        : upstream.status === 404
          ? 404
          : 502,
      upstream.status === 403
        ? "The Library service account does not have Viewer/download access to this file. Share the Library folder with its service-account email as Viewer."
        : message
    );
  }

  if (!upstream.body) {
    throw new HttpError(502, "Google Drive returned an empty file stream.");
  }

  const filename = exportInfo
    ? safeFilename(
        String(metadata.name || "document").replace(/\.[^.]+$/, "") +
          exportInfo.extension
      )
    : safeFilename(metadata.name || "drive-file");

  const responseHeaders = new Headers({
    "Content-Type":
      exportInfo
        ? exportInfo.mimeType
        : upstream.headers.get("content-type") ||
          "application/octet-stream",
    "Content-Disposition":
      "inline; filename*=UTF-8''" + encodeURIComponent(filename),
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
  });

  const length = upstream.headers.get("content-length");
  if (length) responseHeaders.set("Content-Length", length);

  // Pass through the native Fetch stream. No Node.js Readable/Buffer needed.
  return new Response(upstream.body, {
    status: 200,
    headers: responseHeaders,
  });
}

function basicAuthHeader(username, password) {
  const bytes = new TextEncoder().encode(username + ":" + password);
  return "Basic " + btoa(String.fromCharCode(...bytes));
}

async function convertDocxToPdf(urlParams, token, env) {
  const fileId = String(urlParams.get("fileId") || "").trim();
  const resourceKey = String(urlParams.get("resourceKey") || "").trim();

  if (!/^[A-Za-z0-9_-]{10,200}$/.test(fileId)) {
    throw new HttpError(400, "Invalid Google Drive file identifier.");
  }

  const converterBase = getEnvValue(env, "DOCX_PDF_CONVERTER_URL").replace(
    /\/+$/,
    ""
  );
  const converterUser = getEnvValue(env, "DOCX_PDF_CONVERTER_USERNAME");
  const converterPassword = String(
    env && env.DOCX_PDF_CONVERTER_PASSWORD != null
      ? env.DOCX_PDF_CONVERTER_PASSWORD
      : ""
  );

  if (!converterBase || !converterUser || !converterPassword) {
    throw new HttpError(
      503,
      "The DOCX-to-PDF option is not configured on Cloudflare. Add DOCX_PDF_CONVERTER_URL, DOCX_PDF_CONVERTER_USERNAME and DOCX_PDF_CONVERTER_PASSWORD under Worker Settings → Variables and Secrets."
    );
  }

  let converterUrl;
  try {
    converterUrl = new URL(converterBase);
    if (converterUrl.protocol !== "https:") throw new Error("HTTPS required");
  } catch {
    throw new HttpError(
      503,
      "DOCX PDF converter URL must be a valid HTTPS URL."
    );
  }

  if (!(await assertInsideLibrary(fileId, token, resourceKey))) {
    throw new HttpError(
      403,
      "This file is not inside the configured Jupiter Astrology Library folder."
    );
  }

  const metadata = await resolveShortcut(fileId, token, resourceKey);
  const DOCX_MIME =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";
  const isGoogleDoc = metadata.mimeType === GOOGLE_DOC_MIME;

  if (
    !isGoogleDoc &&
    metadata.mimeType !== DOCX_MIME &&
    !/\.docx$/i.test(metadata.name || "")
  ) {
    throw new HttpError(
      415,
      "PDF conversion is currently available for Word DOCX files only."
    );
  }

  if (metadata.capabilities && metadata.capabilities.canDownload === false) {
    throw new HttpError(
      403,
      "The file owner has disabled downloading. This DOCX cannot be converted."
    );
  }

  const driveFileUrl = isGoogleDoc
    ? buildDriveUrl(
        "/files/" + encodeURIComponent(metadata.id) + "/export",
        { mimeType: DOCX_MIME }
      )
    : buildDriveUrl("/files/" + encodeURIComponent(metadata.id), {
        alt: "media",
        supportsAllDrives: "true",
      });

  const driveHeaders = { Authorization: "Bearer " + token };
  if (metadata.resourceKey) {
    driveHeaders["X-Goog-Drive-Resource-Keys"] =
      metadata.id + "/" + metadata.resourceKey;
  }

  const source = await fetch(driveFileUrl.toString(), {
    method: "GET",
    headers: driveHeaders,
  });

  if (!source.ok) {
    const body = await source.json().catch(() => ({}));
    throw new HttpError(
      source.status === 403
        ? 403
        : source.status === 404
          ? 404
          : 502,
      (body.error && body.error.message) ||
        "Google Drive could not retrieve the original DOCX."
    );
  }

  const maxDocxBytes = 50 * 1024 * 1024;
  const contentLength = Number(source.headers.get("content-length") || 0);
  if (contentLength > maxDocxBytes) {
    throw new HttpError(413, "This DOCX exceeds the 50 MB conversion limit.");
  }

  const fileBytes = await source.arrayBuffer();
  if (!fileBytes.byteLength) {
    throw new HttpError(502, "Google Drive returned an empty DOCX.");
  }
  if (fileBytes.byteLength > maxDocxBytes) {
    throw new HttpError(413, "This DOCX exceeds the 50 MB conversion limit.");
  }

  let sourceFilename = metadata.name || "document";
  if (!/\.docx$/i.test(sourceFilename)) sourceFilename += ".docx";

  const form = new FormData();
  form.append(
    "files",
    new Blob([fileBytes], { type: DOCX_MIME }),
    safeFilename(sourceFilename)
  );

  const conversionEndpoint =
    converterBase + "/forms/libreoffice/convert";

  let converted;
  try {
    converted = await fetch(conversionEndpoint, {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(converterUser, converterPassword),
        Accept: "application/pdf",
      },
      body: form,
      signal: AbortSignal.timeout(240_000),
    });
  } catch (error) {
    console.error(
      "DOCX PDF conversion service request failed:",
      error && error.message
    );
    throw new HttpError(
      502,
      "The LibreOffice conversion service could not be reached or timed out."
    );
  }

  if (!converted.ok) {
    const responseText = await converted.text();
    console.error(
      "Gotenberg conversion failed:",
      converted.status,
      responseText.slice(0, 1200)
    );

    throw new HttpError(
      502,
      converted.status === 401
        ? "The LibreOffice conversion service rejected its server credentials. Check the converter username and password in Cloudflare."
        : "LibreOffice could not convert this DOCX to PDF. Check the document and converter service logs."
    );
  }

  const contentType = converted.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/pdf")) {
    const responseText = await converted.text();
    console.error(
      "Unexpected Gotenberg response:",
      contentType,
      responseText.slice(0, 500)
    );
    throw new HttpError(
      502,
      "The conversion service did not return a PDF file."
    );
  }

  if (!converted.body) {
    throw new HttpError(
      502,
      "The conversion service returned an empty PDF file."
    );
  }

  const responseHeaders = new Headers({
    "Content-Type": "application/pdf",
    "Content-Disposition":
      "inline; filename*=UTF-8''" +
      encodeURIComponent(
        String(metadata.name || "document").replace(/\.docx$/i, ".pdf")
      ),
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
  });

  const resultLength = converted.headers.get("content-length");
  if (resultLength) responseHeaders.set("Content-Length", resultLength);

  return new Response(converted.body, {
    status: 200,
    headers: responseHeaders,
  });
}

/**
 * Route this handler from the existing Worker:
 *
 *   if (url.pathname === "/api/drive") {
 *     return handleDriveRequest(request, env);
 *   }
 *
 * The function returns a standard Fetch Response and does not use
 * Node.js request/response objects.
 */
export async function handleDriveRequest(request, env) {
  if (request.method !== "GET") {
    return errorResponse(405, "Method not allowed.", {
      Allow: "GET",
    });
  }

  try {
    const url = new URL(request.url);
    const action = String(url.searchParams.get("action") || "");

    if (
      action !== "download" &&
      action !== "status" &&
      action !== "convert-docx" &&
      action !== "list"
    ) {
      throw new HttpError(400, "Unsupported Drive action.");
    }

    await verifyFirebaseSession(request, env);
    const token = await getGoogleAccessToken(env);

    if (action === "list") {
      return await listFolder(url.searchParams, token);
    }

    if (action === "convert-docx") {
      return await convertDocxToPdf(url.searchParams, token, env);
    }

    if (action === "status") {
      const root = await getMetadata(ROOT_FOLDER_ID, token);
      return jsonResponse(
        {
          configured: true,
          folderId: ROOT_FOLDER_ID,
          folderName: root.name || "Shared Astrology Library",
          permission: "Drive read-only",
        },
        200
      );
    }

    return await downloadFile(url.searchParams, token);
  } catch (error) {
    const status =
      Number(error && error.statusCode) || 502;
    const message =
      error && error.message
        ? error.message
        : "Google Drive preview request failed.";

    console.error("Jupiter Drive preview endpoint:", status, message);

    if (status === 401 || status === 403 || status === 404 || status === 413 || status === 415 || status === 503) {
      return errorResponse(status, message);
    }

    return errorResponse(
      status >= 400 && status < 500 ? status : 502,
      message
    );
  }
}
