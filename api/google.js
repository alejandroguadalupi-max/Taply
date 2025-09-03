// Forzar runtime Node (no Edge)
export const config = { runtime: 'nodejs' };

import crypto from "crypto";

export default async function handler(req, res) {
  // --- BASE URL: usa APP_BASE_URL si existe; si no, infiere del request ---
  const proto = (req.headers["x-forwarded-proto"] || "https").toString().split(",")[0];
  const host  = (req.headers["x-forwarded-host"]  || req.headers.host || "").toString().split(",")[0];
  const envBase = process.env.APP_BASE_URL?.replace(/\/$/, "");   // p.ej. https://taply-zeta.vercel.app
  const base = envBase || (host ? `${proto}://${host}` : "");
  const redirectUri = `${base}/api/google`;

  const clientId     = process.env.GOOGLE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();

  // --- Validaciones tempranas: evita la pantalla "invalid_client" de Google ---
  if (!clientId || !clientId.endsWith(".apps.googleusercontent.com")) {
    return res.status(500).json({
      error: "misconfigured_google_client_id",
      hint: "GOOGLE_CLIENT_ID vacío o NO es un OAuth 2.0 Client ID de tipo Web. Debe acabar en .apps.googleusercontent.com",
    });
  }
  if (!clientSecret) {
    return res.status(500).json({ error: "missing_GOOGLE_CLIENT_SECRET" });
  }
  if (!base) {
    return res.status(500).json({ error: "missing_APP_BASE_URL_or_host" });
  }

  const url   = new URL(req.url, base);
  const code  = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const from  = url.searchParams.get("from") || "login";

  const cookieName = "g_state";
  const isHttps    = base.startsWith("https://");
  const cookieFlags = `Path=/; HttpOnly; SameSite=Lax${isHttps ? "; Secure" : ""}`;

  const readCookies = () =>
    Object.fromEntries(
      (req.headers.cookie || "")
        .split(/; */)
        .filter(Boolean)
        .map(c => {
          const [k, ...r] = c.split("=");
          return [k, decodeURIComponent(r.join("="))];
        })
    );

  // 1) INICIO: no hay `code` -> redirige a Google
  if (!code) {
    const st = crypto.randomUUID();
    res.setHeader("Set-Cookie", `${cookieName}=${encodeURIComponent(st)}; Max-Age=600; ${cookieFlags}`);

    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", "openid email profile");
    auth.searchParams.set("access_type", "offline");
    auth.searchParams.set("prompt", "select_account");
    auth.searchParams.set("state", `${st}|${from}`);

    res.writeHead(302, { Location: auth.toString() });
    return res.end();
  }

  // 2) CALLBACK: viene `code` -> canjea token y crea sesión
  try {
    const cookies  = readCookies();
    const expected = cookies[cookieName];
    if (!expected || !state || !state.startsWith(expected)) {
      return res.status(400).send("invalid_state");
    }

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });

    const token = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error("Google token error:", token);
      return res.status(401).json({ error: "google_token_exchange_failed", details: token });
    }
    if (!token.id_token) {
      return res.status(401).json({ error: "missing_id_token", details: token });
    }

    // Decodificar id_token (JWT)
    const payload = JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64").toString("utf8"));
    const email   = payload.email;
    const name    = payload.name || payload.given_name || email;

    // TODO: integra con tu sistema de sesión:
    // - Busca/crea usuario por email
    // - Crea cookie de sesión (mismo cookieFlags)
    // res.setHeader("Set-Cookie", `taply_session=...; ${cookieFlags}`);

    // Limpia cookie de state
    res.setHeader("Set-Cookie", `${cookieName}=; Max-Age=0; ${cookieFlags}`);

    // Redirige de vuelta a tu app
    res.writeHead(302, { Location: "/suscripciones.html#google=ok" });
    return res.end();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "google_auth_failed" });
  }
}
