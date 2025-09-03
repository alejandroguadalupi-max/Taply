// /api/google.js  (Vercel: pages/api/google.js o api/google.js)
import crypto from "crypto";

export default async function handler(req, res) {
  const base = process.env.APP_BASE_URL;               // p.ej. https://taply-zeta.vercel.app
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = `${base}/api/google`;           // UN SOLO redirect, coincide con Google Cloud

  const url = new URL(req.url, base);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const from  = url.searchParams.get("from") || "login";
  const cookieName = "g_state";

  // Helpers cookies
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
    res.setHeader(
      "Set-Cookie",
      `${cookieName}=${encodeURIComponent(st)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
    );

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
    const cookies = readCookies();
    const expected = cookies[cookieName];
    if (!expected || !state || !state.startsWith(expected)) {
      return res.status(400).send("Invalid state");
    }

    // Intercambia el code por tokens
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
    if (!token.id_token) return res.status(401).json({ error: "google_auth_failed" });

    // Decodifica el id_token (JWT) para obtener email y nombre
    const payload = JSON.parse(
      Buffer.from(token.id_token.split(".")[1], "base64").toString("utf8")
    );
    const email = payload.email;
    const name = payload.name || payload.given_name || email;

    // TODO: aquí integra con TU sistema:
    // - Busca/crea usuario por email
    // - Si ya existía como "normal", NO crees otro (mismo email = misma cuenta)
    // - Crea la cookie de sesión como haces en /api/login
    //   p.ej.: res.setHeader("Set-Cookie", "taply_session=...; Path=/; HttpOnly; Secure; SameSite=Lax");

    // Limpia cookie de state
    res.setHeader("Set-Cookie", `${cookieName}=; Path=/; Max-Age=0`);

    // Vuelve a la página y deja pista para refrescar sesión
    res.writeHead(302, { Location: "/suscripciones.html#google=ok" });
    return res.end();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "google_auth_failed" });
  }
}

