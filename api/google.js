// Fuerza runtime Node (no Edge)
export const config = { runtime: "nodejs" };

import crypto from "crypto";
import jwt from "jsonwebtoken";
import Stripe from "stripe";

const COOKIE_SESSION = "taply_session";
const COOKIE_STATE   = "g_state";

function cookieFlags(isHttps) {
  return `Path=/; HttpOnly; SameSite=Lax${isHttps ? "; Secure" : ""}`;
}
function setSession(res, payload, isHttps) {
  const token = jwt.sign(payload, process.env.APP_SECRET, { expiresIn: "90d" });
  const flags = `${cookieFlags(isHttps)}; Max-Age=${60 * 60 * 24 * 90}`;
  const prev = res.getHeader("Set-Cookie");
  const arr  = Array.isArray(prev) ? prev : prev ? [prev] : [];
  arr.push(`${COOKIE_SESSION}=${token}; ${flags}`);
  res.setHeader("Set-Cookie", arr);
}
function clearStateCookie(res, isHttps) {
  const flags = `${cookieFlags(isHttps)}; Max-Age=0`;
  const prev = res.getHeader("Set-Cookie");
  const arr  = Array.isArray(prev) ? prev : prev ? [prev] : [];
  arr.push(`${COOKIE_STATE}=; ${flags}`);
  res.setHeader("Set-Cookie", arr);
}
function readCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "")
      .split(/; */)
      .filter(Boolean)
      .map((c) => {
        const [k, ...r] = c.split("=");
        return [k, decodeURIComponent(r.join("="))];
      })
  );
}
function normalizeEmail(s = "") {
  return String(s).trim().toLowerCase();
}

export default async function handler(req, res) {
  const envBase = process.env.APP_BASE_URL?.replace(/\/$/, "");
  const proto   = String(req.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host    = String(req.headers["x-forwarded-host"]  || req.headers.host || "").split(",")[0];
  const base    = envBase || (host ? `${proto}://${host}` : "");
  const redirectUri = `${base}/api/google`;
  const isHttps = base.startsWith("https://");

  const clientId     = process.env.GOOGLE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();
  const stripeSecret = process.env.STRIPE_SECRET_KEY;
  const appSecret    = process.env.APP_SECRET;

  const url = new URL(req.url, base || "http://x");
  if (url.searchParams.get("debug") === "1") {
    return res.status(200).json({
      ok: true, base, redirectUri,
      clientIdLooksOk: !!(clientId && clientId.endsWith(".apps.googleusercontent.com")),
      hasClientSecret: !!clientSecret,
      hasStripe: !!stripeSecret,
      hasAppSecret: !!appSecret,
    });
  }

  // Validaciones
  if (!base)        return res.status(500).json({ error: "missing_base_url" });
  if (!clientId || !clientId.endsWith(".apps.googleusercontent.com"))
    return res.status(500).json({ error: "misconfigured_google_client_id" });
  if (!clientSecret) return res.status(500).json({ error: "missing_GOOGLE_CLIENT_SECRET" });
  if (!stripeSecret) return res.status(500).json({ error: "missing_STRIPE_SECRET_KEY" });
  if (!appSecret)    return res.status(500).json({ error: "missing_APP_SECRET" });

  const code   = url.searchParams.get("code");
  const stateQ = url.searchParams.get("state");
  const fromQ  = url.searchParams.get("from") || "login";

  const stripe = new Stripe(stripeSecret, { apiVersion: "2024-06-20" });

  // 1) Inicio → redirigir a Google
  if (!code) {
    const st = crypto.randomUUID();
    res.setHeader("Set-Cookie", `${COOKIE_STATE}=${encodeURIComponent(st)}; Max-Age=600; ${cookieFlags(isHttps)}`);

    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", "openid email profile");
    auth.searchParams.set("access_type", "offline");
    auth.searchParams.set("prompt", "select_account");
    auth.searchParams.set("state", `${st}|${fromQ}`); // guardo de dónde venía (login/register)

    res.writeHead(302, { Location: auth.toString() });
    return res.end();
  }

  // 2) Callback
  try {
    const cookies = readCookies(req);
    const expected = cookies[COOKIE_STATE];
    if (!expected || !stateQ || !stateQ.startsWith(expected)) {
      clearStateCookie(res, isHttps);
      res.writeHead(302, { Location: `/suscripciones.html#google=err&code=state_error&from=${fromQ}` });
      return res.end();
    }
    const from = stateQ.split("|")[1] || fromQ;

    // Intercambio
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code, client_id: clientId, client_secret: clientSecret,
        redirect_uri: redirectUri, grant_type: "authorization_code",
      }),
    });
    const token = await tokenRes.json();
    if (!tokenRes.ok || !token.id_token) {
      clearStateCookie(res, isHttps);
      res.writeHead(302, { Location: `/suscripciones.html#google=err&code=google_auth_failed&from=${from}` });
      return res.end();
    }

    // Decodificar id_token
    const payload = JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64").toString("utf8"));
    const email = normalizeEmail(payload.email || "");
    const name  = payload.name || payload.given_name || email;
    const emailVerified = !!payload.email_verified;
    if (!email || !emailVerified) {
      clearStateCookie(res, isHttps);
      res.writeHead(302, { Location: `/suscripciones.html#google=err&code=email_not_verified&from=${from}` });
      return res.end();
    }

    // Buscar/validar en Stripe
    const found = await stripe.customers.search({ query: `email:'${email.replace(/'/g, "\\'")}'`, limit: 1 });
    const exists    = found.data.length ? found.data[0] : null;
    const hasPass   = !!(exists?.metadata?.taply_pass_hash);
    const hasGoogle = (exists?.metadata?.taply_google === "1" || exists?.metadata?.taply_google === "true");

    if (from === "login") {
      // Solo permitimos login con Google si ya está registrado con Google
      if (!exists || !hasGoogle) {
        clearStateCookie(res, isHttps);
        res.writeHead(302, { Location: `/suscripciones.html#google=err&code=not_registered&from=login` });
        return res.end();
      }
      if (hasPass && !hasGoogle) {
        clearStateCookie(res, isHttps);
        res.writeHead(302, { Location: `/suscripciones.html#google=err&code=use_password_login&from=login` });
        return res.end();
      }
      try {
        await stripe.customers.update(exists.id, {
          name: exists.name || name || undefined,
          metadata: { ...(exists.metadata || {}), app: "taply", taply_google: "1", taply_nfc_qty: exists?.metadata?.taply_nfc_qty || "0" },
        });
      } catch {}
      setSession(res, { email, name: exists.name || name || null, customerId: exists.id }, isHttps);
      clearStateCookie(res, isHttps);
      res.writeHead(302, { Location: `/suscripciones.html#google=ok&from=login` });
      return res.end();
    }

    // from === 'register'
    if (exists) {
      if (hasGoogle) { // ya está registrado con Google
        clearStateCookie(res, isHttps);
        res.writeHead(302, { Location: `/suscripciones.html#google=err&code=email_in_use_google&from=register` });
        return res.end();
      }
      if (hasPass) {   // ya está registrado con password
        clearStateCookie(res, isHttps);
        res.writeHead(302, { Location: `/suscripciones.html#google=err&code=email_in_use_password&from=register` });
        return res.end();
      }
      // existe “huérfano” → lo consideramos en uso
      clearStateCookie(res, isHttps);
      res.writeHead(302, { Location: `/suscripciones.html#google=err&code=email_in_use&from=register` });
      return res.end();
    }

    // Crear cuenta nueva con Google
    const created = await stripe.customers.create({
      email, name: name || undefined, metadata: { app: "taply", taply_google: "1", taply_nfc_qty: "0" },
    });
    setSession(res, { email, name: created.name || name || null, customerId: created.id }, isHttps);
    clearStateCookie(res, isHttps);
    res.writeHead(302, { Location: `/suscripciones.html#google=ok&from=register` });
    return res.end();
  } catch (e) {
    console.error("google oauth error:", e);
    clearStateCookie(res, isHttps);
    res.writeHead(302, { Location: `/suscripciones.html#google=err&code=server_error&from=login` });
    return res.end();
  }
}

