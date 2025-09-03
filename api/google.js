// /api/google.js
// Hace el inicio del flujo OAuth y también recibe el callback.

const crypto = require("crypto");

// Leer cookie simple
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

module.exports = async (req, res) => {
  try {
    const host = req.headers["x-forwarded-host"] || req.headers.host || "localhost:3000";
    const protocol = host.includes("localhost") ? "http" : "https";
    const here = new URL(`${protocol}://${host}${req.url}`);
    const code = here.searchParams.get("code");
    const stateParam = here.searchParams.get("state");

    const BASE = process.env.APP_BASE_URL; // p.ej. https://taply-zeta.vercel.app
    const CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID;
    const CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    if (!BASE || !CLIENT_ID || !CLIENT_SECRET) {
      res.statusCode = 500;
      return res.end("Faltan APP_BASE_URL / GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET");
    }

    const REDIRECT_URI = `${BASE}/api/google`;

    // === CALLBACK (Google nos devuelve ?code=...)
    if (code) {
      const stateCookie = getCookie(req, "g_state");
      if (!stateParam || !stateCookie || stateParam !== stateCookie) {
        res.statusCode = 400;
        return res.end("state inválido");
      }

      // Intercambio code -> tokens
      const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code",
        }),
      });
      const tokens = await tokenResp.json();
      if (!tokenResp.ok || !tokens.id_token) {
        res.statusCode = 400;
        return res.end("No se pudo obtener tokens de Google");
      }

      // Pasamos el id_token a tu endpoint existente para crear la sesión
      const loginResp = await fetch(`${BASE}/api/google-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: tokens.id_token }),
        redirect: "manual",
      });

      // Propagamos la cookie de sesión al navegador
      const setCookie = loginResp.headers.get("set-cookie");
      if (setCookie) res.setHeader("Set-Cookie", setCookie);

      // Eliminamos la cookie de estado
      res.setHeader("Set-Cookie", "g_state=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure");

      // Redirigimos a la página
      res.writeHead(302, { Location: `${BASE}/suscripciones.html#google=ok` });
      return res.end();
    }

    // === START (sin code: lanzamos chooser de cuentas)
    const state = crypto.randomBytes(16).toString("hex");
    const expires = new Date(Date.now() + 10 * 60 * 1000).toUTCString();
    res.setHeader(
      "Set-Cookie",
      `g_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Expires=${expires}`
    );

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid email profile",
      prompt: "select_account",
      access_type: "offline",
      include_granted_scopes: "true",
      state,
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    res.writeHead(302, { Location: authUrl });
    res.end();
  } catch (e) {
    res.statusCode = 500;
    res.end("google error");
  }
};
