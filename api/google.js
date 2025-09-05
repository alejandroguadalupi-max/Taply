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
function baseFromReq(req) {
  const envBase = process.env.APP_BASE_URL?.replace(/\/$/, "");
  const proto   = String(req.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host    = String(req.headers["x-forwarded-host"]  || req.headers.host || "").split(",")[0];
  return envBase || (host ? `${proto}://${host}` : "");
}
function redirect(res, url) {
  res.writeHead(302, { Location: url });
  res.end();
}
function redirectErr(res, from, code = "server_error") {
  redirect(res, `/suscripciones.html#google=err&code=${encodeURIComponent(code)}&from=${encodeURIComponent(from || "login")}`);
}

export default async function handler(req, res) {
  const base        = baseFromReq(req);
  const redirectUri = `${base}/api/google`;
  const isHttps     = base.startsWith("https://");

  const clientId     = process.env.GOOGLE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();
  const stripeSecret = process.env.STRIPE_SECRET_KEY;
  const appSecret    = process.env.APP_SECRET;

  // Debug legible (ES)
  const url = new URL(req.url, base || "http://x");
  const fromQ  = (url.searchParams.get("from") || "login").toLowerCase();
  if (url.searchParams.get("debug") === "1") {
    return res.status(200).json({
      ok: true,
      base, redirectUri,
      clienteGoogleValido: !!(clientId && clientId.endsWith(".apps.googleusercontent.com")),
      tieneSecretoGoogle: !!clientSecret,
      tieneStripe: !!stripeSecret,
      tieneAppSecret: !!appSecret,
      nota: "Si algo falta, en navegación normal se redirige a /suscripciones.html con mensaje en español.",
    });
  }

  // Validaciones: en navegación normal → redirigir con mensaje español
  if (!base)         return redirectErr(res, fromQ, "server_error");
  if (!clientId || !clientId.endsWith(".apps.googleusercontent.com")) return redirectErr(res, fromQ, "server_error");
  if (!clientSecret) return redirectErr(res, fromQ, "server_error");
  if (!stripeSecret) return redirectErr(res, fromQ, "server_error");
  if (!appSecret)    return redirectErr(res, fromQ, "server_error");

  const code   = url.searchParams.get("code");
  const stateQ = url.searchParams.get("state");

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
    auth.searchParams.set("state", `${st}|${fromQ}`); // guardo login/register

    return redirect(res, auth.toString());
  }

  // 2) Callback
  try {
    const cookies  = readCookies(req);
    const expected = cookies[COOKIE_STATE] || "";
    const [stateVal, fromState] = String(stateQ || "").split("|");
    const from = (fromState || fromQ || "login").toLowerCase();

    if (!expected || !stateVal || stateVal !== expected) {
      clearStateCookie(res, isHttps);
      return redirectErr(res, from, "state_error");
    }

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
    if (!tokenRes.ok || !token?.id_token) {
      clearStateCookie(res, isHttps);
      return redirectErr(res, from, "google_auth_failed");
    }

    // Decodificar id_token
    let payload;
    try {
      payload = JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64").toString("utf8"));
    } catch {
      clearStateCookie(res, isHttps);
      return redirectErr(res, from, "google_auth_failed");
    }
    const email = normalizeEmail(payload?.email || "");
    const name  = payload?.name || payload?.given_name || email;
    const emailVerified = !!payload?.email_verified;
    if (!email || !emailVerified) {
      clearStateCookie(res, isHttps);
      return redirectErr(res, from, "email_not_verified");
    }

    // Buscar/validar en Stripe
    const safeEmail = email.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    const found = await stripe.customers.search({ query: `email:'${safeEmail}'`, limit: 1 });
    const exists    = found.data.length ? found.data[0] : null;
    const meta      = exists?.metadata || {};
    const hasPass   = !!meta.taply_pass_hash;
    const hasGoogle = (meta.taply_google === "1" || meta.taply_google === "true");

    if (from === "login") {
      if (!exists) {
        clearStateCookie(res, isHttps);
        return redirectErr(res, "login", "not_registered");
      }
      if (hasPass && !hasGoogle) {
        clearStateCookie(res, isHttps);
        return redirectErr(res, "login", "email_in_use_password");
      }
      if (!hasPass && !hasGoogle) {
        clearStateCookie(res, isHttps);
        return redirectErr(res, "login", "email_in_use");
      }
      try {
        await stripe.customers.update(exists.id, {
          name: exists.name || name || undefined,
          metadata: { ...meta, app: "taply", taply_google: "1", taply_nfc_qty: meta.taply_nfc_qty || "0" },
        });
      } catch {}
      setSession(res, { email, name: exists.name || name || null, customerId: exists.id }, isHttps);
      clearStateCookie(res, isHttps);
      return redirect(res, `/suscripciones.html#google=ok&from=login`);
    }

    // from === 'register'
    if (exists) {
      if (hasGoogle) {
        clearStateCookie(res, isHttps);
        return redirectErr(res, "register", "email_in_use_google");
      }
      if (hasPass) {
        clearStateCookie(res, isHttps);
        return redirectErr(res, "register", "email_in_use_password");
      }
      clearStateCookie(res, isHttps);
      return redirectErr(res, "register", "email_in_use");
    }

    // Crear cuenta nueva con Google
    const created = await stripe.customers.create({
      email, name: name || undefined, metadata: { app: "taply", taply_google: "1", taply_nfc_qty: "0" },
    });
    setSession(res, { email, name: created.name || name || null, customerId: created.id }, isHttps);
    clearStateCookie(res, isHttps);
    return redirect(res, `/suscripciones.html#google=ok&from=register`);
  } catch (e) {
    console.error("google oauth error:", e);
    clearStateCookie(res, isHttps);
    return redirectErr(res, "login", "server_error");
  }
}





