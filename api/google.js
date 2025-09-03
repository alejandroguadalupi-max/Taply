// Fuerza runtime Node (no Edge)
export const config = { runtime: "nodejs" };

import crypto from "crypto";

export default async function handler(req, res) {
  // 1) Base URL: APP_BASE_URL sin / final; si no existe, toma host del request
  const envBase = process.env.APP_BASE_URL?.replace(/\/$/, "");
  const proto   = String(req.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host    = String(req.headers["x-forwarded-host"]  || req.headers.host || "").split(",")[0];
  const base    = envBase || (host ? `${proto}://${host}` : "");
  const redirectUri = `${base}/api/google`;

  // 2) Credenciales
  const clientId     = process.env.GOOGLE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();

  // 3) Modo debug: /api/google?debug=1  (no expone secretos)
  const url = new URL(req.url, base || "http://local.invalid");
  if (url.searchParams.get("debug") === "1") {
    return res.status(200).json({
      ok: true,
      base,
      redirectUri,
      clientIdLooksOk: !!(clientId && clientId.endsWith(".apps.googleusercontent.com")),
      clientIdTail: clientId ? clientId.slice(-18) : null, // última parte para comprobar visualmente
      hasClientSecret: !!clientSecret,
      note: "Si clientIdLooksOk=false, revisa variables en Vercel y vuelve a desplegar.",
    });
  }

  // 4) Validaciones tempranas: así no llegas a la pantalla 'invalid_client' de Google
  if (!base) return res.status(500).json({ error: "missing_base_url", hint: "Define APP_BASE_URL o asegúrate de que llega Host." });
  if (!clientId || !clientId.endsWith(".apps.googleusercontent.com")) {
    return res.status(500).json({
      error: "misconfigured_google_client_id",
      hint: "GOOGLE_CLIENT_ID vacío o incorrecto. Debe terminar en .apps.googleusercontent.com",
    });
  }
  if (!clientSecret) return res.status(500).json({ error: "missing_GOOGLE_CLIENT_SECRET" });

  const code  = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const from  = url.searchParams.get("from") || "login";
  const cookieName = "g_state";
  const isHttps = base.startsWith("https://");
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

  // 5) Primer paso: redirigir a Google
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

  // 6) Callback: canjear código por tokens
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

    const payload = JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64").toString("utf8"));
    const email   = payload.email;
    const name    = payload.name || payload.given_name || email;

    // TODO: crea tu cookie de sesión aquí (igual que en /api/login)
    // res.setHeader("Set-Cookie", `taply_session=...; ${cookieFlags}`);

    // Limpia estado y vuelve a la app
    res.setHeader("Set-Cookie", `${cookieName}=; Max-Age=0; ${cookieFlags}`);
    res.writeHead(302, { Location: "/suscripciones.html#google=ok" });
    return res.end();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "google_auth_failed" });
  }
}
