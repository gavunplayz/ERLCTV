const SITE_ORIGIN = "https://gavunplayz.github.io";
const SITE_RETURN_URL = "https://gavunplayz.github.io/ERlCTV/";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const STATE_COOKIE = "__Host-erlctv_oauth_state";
const STATE_SECONDS = 60 * 10;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/auth/")) {
      if (request.method === "OPTIONS") return corsPreflight(request);
      try {
        let response;
        if (url.pathname === "/auth/discord" && request.method === "GET") {
          response = await startDiscordLogin(request, env);
        } else if (url.pathname === "/auth/callback" && request.method === "GET") {
          response = await finishDiscordLogin(request, env);
        } else if (url.pathname === "/auth/me" && request.method === "GET") {
          response = await getCurrentUser(request, env);
        } else if (url.pathname === "/auth/logout" && request.method === "POST") {
          response = json({ success: true });
        } else {
          response = json({ error: "Not found" }, 404);
        }
        return addCorsHeaders(response, request);
      } catch (error) {
        console.error("ER:LC TV authentication error:", error);
        return addCorsHeaders(json({ error: "Authentication service temporarily unavailable." }, 500), request);
      }
    }

    return env.ASSETS.fetch(request);
  }
};

function requiredEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing Worker secret: ${name}`);
  return value;
}

function corsPreflight(request) {
  const origin = request.headers.get("Origin");
  if (origin !== SITE_ORIGIN) return new Response(null, { status: 403 });
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
  const origin = request.headers.get("Origin");
  if (origin === SITE_ORIGIN) {
    headers.set("Access-Control-Allow-Origin", SITE_ORIGIN);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    headers.set("Vary", "Origin");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
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
    headers: {
      Location: authorizeUrl.toString(),
      "Set-Cookie": stateCookie(state),
      "Cache-Control": "no-store"
    }
  });
}

async function finishDiscordLogin(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const savedState = readCookie(request, STATE_COOKIE);
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    return new Response("Discord sign-in was cancelled. Return to ER:LC TV and try again.", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Set-Cookie": clearStateCookie(), "Cache-Control": "no-store" }
    });
  }

  if (!code || !returnedState || !savedState || returnedState !== savedState) {
    return new Response("Sign-in could not be verified. Return to ER:LC TV and try again.", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Set-Cookie": clearStateCookie(), "Cache-Control": "no-store" }
    });
  }

  const clientId = requiredEnv(env, "DISCORD_CLIENT_ID");
  const clientSecret = requiredEnv(env, "DISCORD_CLIENT_SECRET");
  const redirectUri = new URL("/auth/callback", request.url).toString();

  const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri
    })
  });

  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Discord token exchange failed:", tokenData.error || tokenResponse.status);
    return new Response("Discord sign-in could not be completed. Please try again.", { status: 502 });
  }

  const userResponse = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  const discordUser = await userResponse.json();

  if (!userResponse.ok || !discordUser.id || !discordUser.username) {
    console.error("Discord profile request failed:", userResponse.status);
    return new Response("We couldn't retrieve your Discord profile. Please try again.", { status: 502 });
  }

  const sessionUser = {
    id: String(discordUser.id),
    username: String(discordUser.username),
    displayName: String(discordUser.global_name || discordUser.username),
    avatarUrl: discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png?size=128`
      : null,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  };

  const session = await signSession(sessionUser, requiredEnv(env, "SESSION_SECRET"));
  const returnUrl = new URL(SITE_RETURN_URL);
  returnUrl.hash = new URLSearchParams({ session }).toString();

  return new Response(null, {
    status: 302,
    headers: {
      Location: returnUrl.toString(),
      "Set-Cookie": clearStateCookie(),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer"
    }
  });
}

async function getCurrentUser(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer (.+)$/i);
  if (!match) return json({ authenticated: false }, 401);

  const user = await verifySession(match[1], requiredEnv(env, "SESSION_SECRET"));
  if (!user) return json({ authenticated: false }, 401);

  return json({
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl
    }
  });
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
    const bodyBytes = base64UrlDecode(parts[0]);
    const signature = base64UrlDecode(parts[1]);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(bodyBytes));
    if (!payload.id || !payload.username || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
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

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

function stateCookie(value) {
  return `${STATE_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${STATE_SECONDS}`;
}

function clearStateCookie() {
  return `${STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}