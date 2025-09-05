// api/google.js
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
function normalizeEmail(s = "") { return String(s).trim().toLowerCase(); }
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
function escapeStripeQueryValue(v=''){ return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }

function invalidOrExpiredHtml(res, email=''){
  res.setHeader('Content-Type','text/html; charset=utf-8');
  return res.end(`<!doctype html><meta charset="utf-8">
  <title>Enlace inválido</title>
  <style>
    body{font-family:system-ui,Segoe UI,Inter,sans-serif;background:#0b0f1a;color:#e9eefc;display:grid;place-items:center;height:100vh;margin:0}
    .card{background:#0e1424;border:1px solid rgba(255,255,255,.12);padding:22px;border-radius:14px;max-width:520px;text-align:center}
    button{padding:10px 14px;border-radius:10px;background:#7c3aed;color:#fff;border:0;cursor:pointer}
    input{width:100%;padding:8px;border-radius:8px;border:1px solid #334;background:#0b1020;color:#e9eefc}
  </style>
  <div class="card">
    <h2>Enlace inválido o caducado</h2>
    <p>Vuelve a solicitar el correo de verificación.</p>
    <div style="margin-top:12px">
      <input id="em" placeholder="tu@email.com" value="${email||''}" />
    </div>
    <div style="margin-top:12px">
      <button onclick="(async()=>{const r=await fetch('/api/resend-verification',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('em').value})});const d=await r.json();alert(d.message||'Listo');})()">Reenviar verificación</button>
    </div>
  </div>`);
}

async function verifyEmailFlow(req, res, stripe) {
  const url = new URL(req.url, 'http://x');
  const token = (url.searchParams.get('token') || url.searchParams.get('t') || '').trim();
  let email   = normalizeEmail(url.searchParams.get('email') || url.searchParams.get('e') || '');

  if(!token && !email){
    res.statusCode = 400;
    res.setHeader("Content-Type","text/plain; charset=utf-8");
    return res.end("Parámetros inválidos.");
  }

  try{
    let customer = null;

    // 1) Si tengo email, busco por email
    if(email){
      const qEmail = `email:'${escapeStripeQueryValue(email)}'`;
      const found = await stripe.customers.search({ query: qEmail, limit: 1 });
      customer = found.data[0] || null;
    }

    // 2) Si no encontré por email, o no venía email, intento por token
    if(!customer && token){
      const qTok = `metadata['taply_email_token']:'${escapeStripeQueryValue(token)}'`;
      const foundTok = await stripe.customers.search({ query: qTok, limit: 1 });
      customer = foundTok.data[0] || null;
      if(customer && !email) email = normalizeEmail(customer.email || '');
    }

    if(!customer) return invalidOrExpiredHtml(res, email);

    const exp = Number(customer.metadata?.taply_email_exp || '0');
    const saved = customer.metadata?.taply_email_token || '';
    if (!token || saved !== token || exp < Math.floor(Date.now()/1000)) {
      return invalidOrExpiredHtml(res, email);
    }

    await stripe.customers.update(customer.id, { metadata: { ...(customer.metadata||{}), taply_email_verified:'1', taply_email_token:'', taply_email_exp:'' }});

    const html = `<!doctype html><meta charset="utf-8">
    <title>Correo verificado</title>
    <style>body{font-family:system-ui,Segoe UI,Inter,sans-serif;background:#0b0f1a;color:#e9eefc;display:grid;place-items:center;height:100vh;margin:0}
    .card{background:#0e1424;border:1px solid rgba(255,255,255,.12);padding:22px;border-radius:14px;max-width:520px;text-align:center}
    a{color:#9ad2ff}</style>
    <div class="card">
      <h2>¡Correo verificado!</h2>
      <p>Tu cuenta ha sido activada.</p>
      <p><a href="/suscripciones.html">Continuar</a></p>
    </div>
    <script>
      (async ()=>{
        try{
          const r = await fetch('/api/session'); const d = await r.json();
          localStorage.setItem('acct_user', JSON.stringify(d.user||null));
          setTimeout(()=>{ location.replace('/suscripciones.html#email=verified'); }, 600);
        }catch{
          location.replace('/suscripciones.html#email=verified');
        }
      })();
    </script>`;
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.end(html);
  }catch(e){
    console.error("verifyEmailFlow error:", e?.message || e);
    res.statusCode = 500;
    return res.end("Error verificando el correo.");
  }
}

export default async function handler(req, res) {
  const base        = baseFromReq(req);
  const redirectUri = `${base}/api/google`;
  const isHttps     = base.startsWith("https://");

  const clientId     = process.env.GOOGLE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();
  const stripeSecret = process.env.STRIPE_SECRET_KEY;
  const appSecret    = process.env.APP_SECRET;

  const url = new URL(req.url, base || "http://x");
  const fromQ  = (url.searchParams.get("from") || "login").toLowerCase();

  // Verificación de email (enlace desde el correo)
  if (url.searchParams.get("__verify") === "1") {
    if (!stripeSecret) { res.statusCode=500; return res.end("Config Stripe ausente."); }
    const stripe = new Stripe(stripeSecret, { apiVersion: "2024-06-20" });
    return verifyEmailFlow(req, res, stripe);
  }

  // Debug
  if (url.searchParams.get("debug") === "1") {
    return res.status(200).json({
      ok: true, base, redirectUri,
      clienteGoogleValido: !!(clientId && clientId.endsWith(".apps.googleusercontent.com")),
      tieneSecretoGoogle: !!clientSecret,
      tieneStripe: !!stripeSecret,
      tieneAppSecret: !!appSecret,
    });
  }

  // Validaciones mínimas
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
    auth.searchParams.set("state", `${st}|${fromQ}`);
    return redirect(res, auth.toString());
  }

  // 2) Callback OAuth
  try {
    const cookies  = readCookies(req);
    const expected = cookies[COOKIE_STATE] || "";
    const [stateVal, fromState] = String(stateQ || "").split("|");
    const from = (fromState || fromQ || "login").toLowerCase();

    if (!expected || !stateVal || stateVal !== expected) {
      clearStateCookie(res, isHttps);
      return redirectErr(res, from, "state_error");
    }

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

    const safeEmail = escapeStripeQueryValue(email);
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
          metadata: { ...meta, app: "taply", taply_google: "1", taply_nfc_qty: meta.taply_nfc_qty || "0", taply_email_verified:"1" },
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

    const created = await stripe.customers.create({
      email, name: name || undefined, metadata: { app: "taply", taply_google: "1", taply_nfc_qty: "0", taply_email_verified:"1" },
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
