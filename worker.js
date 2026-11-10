const SITE_ORIGIN = "https://gavunplayz.github.io";
const SITE_RETURN_URL = "https://gavunplayz.github.io/ERLCTV/";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const DISCORD_STATE_COOKIE = "__Host-erlctv_oauth_state";
const YOUTUBE_STATE_COOKIE = "__Host-erlctv_youtube_state";
const STATE_SECONDS = 60 * 10;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith("/auth/") || path.startsWith("/channels") || path.startsWith("/youtube/")) {
      if (request.method === "OPTIONS") return corsPreflight(request);
      try {
        let response;
        if (path === "/auth/discord" && request.method === "GET") response = await startDiscordLogin(request, env);
        else if (path === "/auth/callback" && request.method === "GET") response = await finishDiscordLogin(request, env);
        else if (path === "/auth/me" && request.method === "GET") response = await getCurrentUser(request, env);
        else if (path === "/auth/logout" && request.method === "POST") response = json({ success: true });
        else if (path === "/channels" && request.method === "GET") response = await listMyChannels(request, env);
        else if (path === "/channels/connect" && request.method === "POST") response = await beginChannelConnection(request, env);
        else if (path === "/channels/public" && request.method === "GET") response = await getPublicChannel(url, env);
        else if (path === "/youtube/callback" && request.method === "GET") response = await finishYouTubeConnection(request, env);
        else response = json({ error: "Not found" }, 404);
        return addCorsHeaders(response, request);
      } catch (error) {
        console.error("ER:LC TV API error:", error);
        return addCorsHeaders(json({ error: "The service is temporarily unavailable. Please try again." }, 500), request);
      }
    }
    return env.ASSETS.fetch(request);
  }
};

function requiredEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error("Missing Worker secret: " + name);
  return value;
}

function requireDatabase(env) {
  if (!env.DB) throw new Error("Missing D1 binding: DB");
  return env.DB;
}

function corsPreflight(request) {
  if (request.headers.get("Origin") !== SITE_ORIGIN) return new Response(null, { status: 403 });
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": SITE_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

function addCorsHeaders(response, request) {
  const headers = new Headers(response.headers);
  if (request.headers.get("Origin") === SITE_ORIGIN) {
    headers.set("Access-Control-Allow-Origin", SITE_ORIGIN);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    headers.set("Vary", "Origin");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function startDiscordLogin(request, env) {
  const clientId = requiredEnv(env, "DISCORD_CLIENT_ID");
  const state = randomToken(32);
  const redirectUri = new URL("/auth/callback", request.url).toString();
  const authorizeUrl = new URL("https://discord.com/oauth2/authorize");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", "identify");
  authorizeUrl.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: { Location: authorizeUrl.toString(), "Set-Cookie": cookie(DISCORD_STATE_COOKIE, state, STATE_SECONDS), "Cache-Control": "no-store" }
  });
}

async function finishDiscordLogin(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const savedState = readCookie(request, DISCORD_STATE_COOKIE);
  if (url.searchParams.has("error")) return textRedirect("Discord sign-in was cancelled.", "auth_error");
  if (!code || !returnedState || !savedState || returnedState !== savedState) return textRedirect("Discord sign-in could not be verified.", "auth_error");

  const clientId = requiredEnv(env, "DISCORD_CLIENT_ID");
  const clientSecret = requiredEnv(env, "DISCORD_CLIENT_SECRET");
  const redirectUri = new URL("/auth/callback", request.url).toString();
  const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri })
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Discord token exchange failed:", tokenData.error || tokenResponse.status);
    return textRedirect("Discord sign-in could not be completed.", "auth_error");
  }
  const userResponse = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tokenData.access_token } });
  const discordUser = await userResponse.json();
  if (!userResponse.ok || !discordUser.id || !discordUser.username) return textRedirect("We couldn't retrieve your Discord profile.", "auth_error");

  const sessionUser = {
    id: String(discordUser.id),
    username: String(discordUser.username),
    displayName: String(discordUser.global_name || discordUser.username),
    avatarUrl: discordUser.avatar ? "https://cdn.discordapp.com/avatars/" + discordUser.id + "/" + discordUser.avatar + ".png?size=128" : null,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  };
  const session = await signSession(sessionUser, requiredEnv(env, "SESSION_SECRET"));
  const returnUrl = new URL(SITE_RETURN_URL);
  returnUrl.hash = new URLSearchParams({ session }).toString();
  return new Response(null, {
    status: 302,
    headers: { Location: returnUrl.toString(), "Set-Cookie": clearCookie(DISCORD_STATE_COOKIE), "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" }
  });
}

async function getCurrentUser(request, env) {
  const user = await authenticatedUser(request, env);
  if (!user) return json({ authenticated: false }, 401);
  return json({ authenticated: true, user: publicUser(user) });
}

async function authenticatedUser(request, env) {
  const match = (request.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return verifySession(match[1], requiredEnv(env, "SESSION_SECRET"));
}

async function listMyChannels(request, env) {
  const user = await authenticatedUser(request, env);
  if (!user) return json({ error: "Please sign in again." }, 401);
  const db = requireDatabase(env);
  const result = await db.prepare(
    "SELECT id, name, slug, description, youtube_channel_id, youtube_channel_title, youtube_thumbnail_url, created_at FROM channels WHERE owner_discord_id = ? ORDER BY created_at DESC"
  ).bind(user.id).all();
  return json({ channels: result.results || [], limit: 3 });
}

async function beginChannelConnection(request, env) {
  const user = await authenticatedUser(request, env);
  if (!user) return json({ error: "Please sign in with Discord first." }, 401);
  const db = requireDatabase(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Please enter valid channel details." }, 400); }

  const name = String(body.name || "").trim();
  const description = String(body.description || "").trim();
  const slug = makeSlug(body.slug || name);
  if (name.length < 2 || name.length > 40) return json({ error: "Channel name must be between 2 and 40 characters." }, 400);
  if (description.length > 160) return json({ error: "Description must be 160 characters or fewer." }, 400);
  if (!slug || slug.length < 3 || slug.length > 30) return json({ error: "Choose a channel URL between 3 and 30 characters using letters, numbers, and hyphens." }, 400);

  const owned = await db.prepare("SELECT COUNT(*) AS total FROM channels WHERE owner_discord_id = ?").bind(user.id).first();
  if (Number(owned?.total || 0) >= 3) return json({ error: "Each Discord account can create up to 3 channels." }, 409);
  const slugExists = await db.prepare("SELECT id FROM channels WHERE slug = ? UNION ALL SELECT id FROM pending_channels WHERE slug = ? AND expires_at > ? LIMIT 1")
    .bind(slug, slug, Math.floor(Date.now() / 1000)).first();
  if (slugExists) return json({ error: "That channel URL is already taken. Try another one." }, 409);

  const state = randomToken(32);
  const stateHash = await sha256Hex(state);
  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  await db.prepare("DELETE FROM pending_channels WHERE expires_at <= ?").bind(now).run();
  await db.prepare(
    "INSERT INTO pending_channels (id, owner_discord_id, name, slug, description, state_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, user.id, name, slug, description, stateHash, now + STATE_SECONDS).run();

  const clientId = requiredEnv(env, "GOOGLE_CLIENT_ID");
  const redirectUri = new URL("/youtube/callback", request.url).toString();
  const googleUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  googleUrl.searchParams.set("client_id", clientId);
  googleUrl.searchParams.set("redirect_uri", redirectUri);
  googleUrl.searchParams.set("response_type", "code");
  googleUrl.searchParams.set("scope", "https://www.googleapis.com/auth/youtube.readonly");
  googleUrl.searchParams.set("access_type", "offline");
  googleUrl.searchParams.set("prompt", "consent");
  googleUrl.searchParams.set("include_granted_scopes", "true");
  googleUrl.searchParams.set("state", state);
  return json({ authorizeUrl: googleUrl.toString() });
}

async function finishYouTubeConnection(request, env) {
  const url = new URL(request.url);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (url.searchParams.has("error")) return channelRedirect("google_cancelled");
  if (!state || !code) return channelRedirect("google_state_error");

  const db = requireDatabase(env);
  const stateHash = await sha256Hex(state);
  const pending = await db.prepare(
    "SELECT id, owner_discord_id, name, slug, description FROM pending_channels WHERE state_hash = ? AND expires_at > ? LIMIT 1"
  ).bind(stateHash, Math.floor(Date.now() / 1000)).first();
  if (!pending) return channelRedirect("setup_expired");

  const clientId = requiredEnv(env, "GOOGLE_CLIENT_ID");
  const clientSecret = requiredEnv(env, "GOOGLE_CLIENT_SECRET");
  const redirectUri = new URL("/youtube/callback", request.url).toString();
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code"
    })
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Google token exchange failed:", tokenData.error || tokenResponse.status);
    await deletePending(db, pending.id);
    return channelRedirect("google_token_error");
  }

  const channelResponse = await fetch("https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true", {
    headers: { Authorization: "Bearer " + tokenData.access_token }
  });
  const channelData = await channelResponse.json();
  const youtubeChannel = channelData.items && channelData.items[0];
  if (!channelResponse.ok || !youtubeChannel?.id) {
    console.error("YouTube channel lookup failed:", channelData.error?.message || channelResponse.status);
    await deletePending(db, pending.id);
    return channelRedirect("youtube_channel_missing");
  }
  if (!tokenData.refresh_token) {
    await deletePending(db, pending.id);
    return channelRedirect("refresh_token_missing");
  }

  const encryptedRefreshToken = await encryptRefreshToken(tokenData.refresh_token, requiredEnv(env, "YOUTUBE_TOKEN_ENCRYPTION_KEY"));
  const title = String(youtubeChannel.snippet?.title || "YouTube channel").slice(0, 100);
  const thumbnail = youtubeChannel.snippet?.thumbnails?.default?.url || null;
  let insert;
  try {
    insert = await db.prepare(
      "INSERT INTO channels (id, owner_discord_id, name, slug, description, youtube_channel_id, youtube_channel_title, youtube_thumbnail_url, youtube_refresh_token_enc) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM channels WHERE owner_discord_id = ?) < 3"
    ).bind(
      pending.id, pending.owner_discord_id, pending.name, pending.slug, pending.description,
      youtubeChannel.id, title, thumbnail, encryptedRefreshToken, pending.owner_discord_id
    ).run();
  } catch (error) {
    console.error("Channel insert rejected (likely duplicate URL or YouTube account):", error);
    await deletePending(db, pending.id);
    return channelRedirect("channel_limit_or_taken");
  }
  await deletePending(db, pending.id);

  if (Number(insert.meta?.changes || 0) !== 1) return channelRedirect("channel_limit_or_taken");
  return channelRedirect("created");
}

async function getPublicChannel(url, env) {
  const slug = makeSlug(url.searchParams.get("slug") || "");
  if (!slug) return json({ error: "A channel URL is required." }, 400);
  const db = requireDatabase(env);
  const channel = await db.prepare(
    "SELECT name, slug, description, youtube_channel_id, youtube_channel_title, youtube_thumbnail_url, created_at FROM channels WHERE slug = ? LIMIT 1"
  ).bind(slug).first();
  if (!channel) return json({ error: "Channel not found." }, 404);
  return json({ channel });
}

async function deletePending(db, id) {
  await db.prepare("DELETE FROM pending_channels WHERE id = ?").bind(id).run();
}

function channelRedirect(status) {
  const target = new URL(SITE_RETURN_URL);
  target.searchParams.set("channel_status", status);
  return new Response(null, {
    status: 302,
    headers: { Location: target.toString(), "Set-Cookie": clearCookie(YOUTUBE_STATE_COOKIE), "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" }
  });
}

function textRedirect(message, parameter) {
  const target = new URL(SITE_RETURN_URL);
  target.searchParams.set(parameter, message);
  return new Response(null, { status: 302, headers: { Location: target.toString(), "Set-Cookie": clearCookie(DISCORD_STATE_COOKIE), "Cache-Control": "no-store" } });
}

function publicUser(user) {
  return { id: user.id, username: user.username, displayName: user.displayName, avatarUrl: user.avatarUrl };
}

async function signSession(payload, secret) {
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacSign(body, secret);
  return body + "." + base64UrlEncode(signature);
}

async function verifySession(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, base64UrlDecode(parts[1]), new TextEncoder().encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    if (!payload.id || !payload.username || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

async function encryptRefreshToken(token, base64Key) {
  const keyBytes = Uint8Array.from(atob(base64Key), char => char.charCodeAt(0));
  if (keyBytes.length !== 32) throw new Error("YOUTUBE_TOKEN_ENCRYPTION_KEY must be a Base64-encoded 32-byte key.");
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(token));
  return base64UrlEncode(iv) + "." + base64UrlEncode(new Uint8Array(encrypted));
}

function randomToken(byteLength) {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function makeSlug(value) {
  return String(value || "").toLowerCase().trim().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").replace(/-+/g, "-");
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

function cookie(name, value, maxAge) {
  return name + "=" + value + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + maxAge;
}

function clearCookie(name) {
  return name + "=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}
