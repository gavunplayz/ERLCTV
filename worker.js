const SESSION_COOKIE = "__Host-erlctv_session";
const STATE_COOKIE = "__Host-erlctv_oauth_state";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const STATE_SECONDS = 60 * 10;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/auth/discord" && request.method === "GET") {
        return startDiscordLogin(request, env);
      }

      if (url.pathname === "/auth/callback" && request.method === "GET") {
        return finishDiscordLogin(request, env);
      }

      if (url.pathname === "/auth/me" && request.method === "GET") {
        return getCurrentUser(request, env);
      }

      if (url.pathname === "/auth/logout" && request.method === "POST") {
        return logout(request);
      }

      if (url.pathname.startsWith("/auth/")) {
        return json({ error: "Not found" }, 404);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("ER:LC TV authentication error:", error);
      return json({ error: "Authentication service temporarily unavailable." }, 500);
    }
  }
};

function requiredEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing Worker secret: ${name}`);
  return value;
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
      "Set-Cookie": cookie(STATE_COOKIE, state, STATE_SECONDS),
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
    return new Response("Discord sign-in was cancelled. You can return to ER:LC TV and try again.", {
      status: 400,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Set-Cookie": clearCookie(STATE_COOKIE),
        "Cache-Control": "no-store"
      }
    });
  }

  if (url.searchParams.get("iss") !== "https://discord.com") {
    return new Response("The sign-in provider could not be verified. Please try again.", {
      status: 400,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Set-Cookie": clearCookie(STATE_COOKIE),
        "Cache-Control": "no-store"
      }
    });
  }

  if (!code || !returnedState || !savedState || returnedState !== savedState) {
    return new Response("Sign-in could not be verified. Please return to ER:LC TV and try again.", {
      status: 400,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Set-Cookie": clearCookie(STATE_COOKIE),
        "Cache-Control": "no-store"
      }
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
    return new Response("Discord sign-in could not be completed. Please try again.", {
      status: 502,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Set-Cookie": clearCookie(STATE_COOKIE),
        "Cache-Control": "no-store"
      }
    });
  }

  const userResponse = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });

  const discordUser = await userResponse.json();
  if (!userResponse.ok || !discordUser.id || !discordUser.username) {
    console.error("Discord profile request failed:", userResponse.status);
    return new Response("We couldn't retrieve your Discord profile. Please try again.", {
      status: 502,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Set-Cookie": clearCookie(STATE_COOKIE),
        "Cache-Control": "no-store"
      }
    });
  }

  // Only keep public profile details. The Discord access token is not stored.
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
  const headers = new Headers({
    Location: "/",
    "Cache-Control": "no-store"
  });
  headers.append("Set-Cookie", cookie(SESSION_COOKIE, session, SESSION_SECONDS));
  headers.append("Set-Cookie", clearCookie(STATE_COOKIE));

  return new Response(null, { status: 302, headers });
}

async function getCurrentUser(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return json({ authenticated: false });

  const user = await verifySession(token, requiredEnv(env, "SESSION_SECRET"));
  if (!user) {
    return new Response(JSON.stringify({ authenticated: false }), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": clearCookie(SESSION_COOKIE),
        "Cache-Control": "no-store"
      }
    });
  }

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

function logout(request) {
  const origin = request.headers.get("Origin");
  const ownOrigin = new URL(request.url).origin;
  if (origin && origin !== ownOrigin) return json({ error: "Invalid request origin." }, 403);

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": clearCookie(SESSION_COOKIE),
      "Cache-Control": "no-store"
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
    if (!payload.id || !payload.username || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
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
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return base64UrlEncode(bytes);
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

function cookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
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
