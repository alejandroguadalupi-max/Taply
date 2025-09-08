// api/[...taply].js
export const config = { runtime: "nodejs" };

import Stripe from 'stripe';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import crypto from 'node:crypto';

const COOKIE_NAME = 'taply_session';
const RESET_TTL_SECONDS = 60 * 60; // 1 hora
const EMAIL_VERIFY_TTL_SECONDS = 60 * 60 * 24; // 24h

const PRICES = {
  monthly: {
    basic: process.env.PRICE_ID_BASIC_MONTH,
    medio: process.env.PRICE_ID_MEDIO_MONTH,
    pro:   process.env.PRICE_ID_PRO_MONTH,
  },
  annual: {
    basic: process.env.PRICE_ID_BASIC_YEAR,
    medio: process.env.PRICE_ID_MEDIO_YEAR,
    pro:   process.env.PRICE_ID_PRO_YEAR,
  },
};
const PRICE_ID_NFC = process.env.PRICE_ID_NFC;

/* ===== Utils ===== */
function assertEnv() {
  if (!process.env.APP_SECRET) throw Object.assign(new Error('missing APP_SECRET'), { statusCode: 500 });
  if (!process.env.STRIPE_SECRET_KEY) throw Object.assign(new Error('missing STRIPE_SECRET_KEY'), { statusCode: 500 });
}
function baseUrl(req) {
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0];
  const host  = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0];
  return `${proto}://${host}`;
}
function appBase(req){
  return (process.env.APP_BASE_URL || process.env.BASE_URL || baseUrl(req)).replace(/\/+$/,'');
}
function getBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body); } catch { return {}; }
}
function getCookies(req){ try{ return cookie.parse(req.headers.cookie || ''); }catch{ return {}; } }
function normalizeEmail(email=''){ return String(email).trim().toLowerCase(); }
function setSession(res, payload){
  const token = jwt.sign(payload, process.env.APP_SECRET, { expiresIn: '90d' });
  const isProd = process.env.NODE_ENV === 'production';
  const prev = res.getHeader('Set-Cookie');
  const arr = Array.isArray(prev) ? prev : prev ? [prev] : [];
  arr.push(cookie.serialize(COOKIE_NAME, token, {
    httpOnly:true, secure:isProd, sameSite:'lax', path:'/', maxAge:60*60*24*90
  }));
  res.setHeader('Set-Cookie', arr);
}
function clearSession(res){
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, '', {
    httpOnly:true, secure:isProd, sameSite:'lax', path:'/', maxAge:0
  }));
}
function getSessionFromCookie(req){
  const token = getCookies(req)[COOKIE_NAME];
  if(!token) return null;
  try { return jwt.verify(token, process.env.APP_SECRET); } catch { return null; }
}
function routeOf(req){
  const u = new URL(req.url, 'http://x');
  const p = u.pathname.replace(/^\/+/, '');
  return p.startsWith('api/') ? p.slice(4) : p;
}

/* ===== Stripe helpers ===== */
let stripeSingleton = null;
function getStripe(){
  if (!stripeSingleton) stripeSingleton = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
  return stripeSingleton;
}
function escapeStripeQueryValue(v=''){ return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
async function ensureCustomerId(stripe, sess){
  if(sess?.customerId) return sess.customerId;
  if(!sess?.email) return null;
  const q = `email:'${escapeStripeQueryValue(sess.email)}'`;
  const found = await stripe.customers.search({ query: q, limit: 1 });
  if(found.data.length) {
    const id = found.data[0].id;
    if (sess.name && !found.data[0].name) { try{ await stripe.customers.update(id, { name: sess.name }); }catch{} }
    return id;
  }
  const created = await stripe.customers.create({ email: sess.email, name: sess.name || undefined, metadata:{ app:'taply', taply_nfc_qty: '0' }});
  return created.id;
}
function normalizeSub(sub){
  if(!sub) return null;
  const price = sub.items?.data?.[0]?.price || null;
  const interval = price?.recurring?.interval || sub.plan?.interval || null;
  return {
    id: sub.id,
    status: sub.status,
    cancel_at_period_end: !!sub.cancel_at_period_end,
    current_period_end: sub.current_period_end,
    current_period_start: sub.current_period_start,
    plan: { nickname: price?.nickname || sub.plan?.nickname || null },
    price: { id: price?.id || null, nickname: price?.nickname || null, interval: interval || null },
    schedule_id: sub.schedule || null
  };
}
async function getBestSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', expand: ['data.items.data.price'] });
  const order = { active:3, trialing:2, past_due:1 };
  const best = subs.data.sort((a,b)=> (order[b.status]||0)-(order[a.status]||0) || (b.current_period_end||0)-(a.current_period_end||0))[0];
  return best || null;
}
async function hasValidSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
  return subs.data.some(s => ['active','trialing','past_due'].includes(s.status));
}
function addDays(d, days){ return new Date(d.getTime() + days*24*60*60*1000); }

/* ===== Email (Sendgrid) con reintentos ===== */
/* ===== Email (Sendgrid) con parsing robusto ===== */
/* ===== Email (Sendgrid) robusto ===== */
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
async function withTimeout(promise, ms){
  let t; const timeout = new Promise((_,rej)=> t=setTimeout(()=>rej(Object.assign(new Error('email_timeout'),{code:'email_timeout'})), ms));
  try { return await Promise.race([promise, timeout]); }
  finally { clearTimeout(t); }
}
function parseAddress(v=''){
  const s = String(v).trim();
  const m = s.match(/^(?:"?([^"<]+)"?\s*)?<\s*([^>]+)\s*>$/);
  if (m) return { email: m[2].trim(), name: (m[1]||'').trim() || undefined };
  return { email: s, name: undefined };
}
function isTaplyEmail(v=''){ return /@taply\.es$/i.test(String(v).trim()); }

async function sendEmail({to, subject, text, html}){
  try{
    const RAW_FROM  = (process.env.EMAIL_FROM || '').trim();
    const RAW_REPLY = (process.env.EMAIL_REPLY_TO || '').trim();

    if(!process.env.SENDGRID_API_KEY || !RAW_FROM || !to){
      console.warn('sendEmail: falta cfg', { hasKey:!!process.env.SENDGRID_API_KEY, RAW_FROM, to });
      return false;
    }

    const { default: sgMail } = await import('@sendgrid/mail');
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);

    const fromParsed  = parseAddress(RAW_FROM);
    const replyParsed = RAW_REPLY ? parseAddress(RAW_REPLY) : null;

    if (!isTaplyEmail(fromParsed.email)) {
      console.error('EMAIL_FROM debe ser @taply.es. Valor actual:', fromParsed.email);
      return false;
    }
    const replyTo = replyParsed && isTaplyEmail(replyParsed.email)
      ? { email: replyParsed.email, name: replyParsed.name }
      : undefined;

    const isVerify = /Confirma tu correo/i.test(subject) || /\/api\/verify-email/i.test(String(html||''));
    const payload = {
      to,
      from: { email: fromParsed.email, name: fromParsed.name || 'Taply' },
      ...(replyTo ? { replyTo } : {}),
      subject,
      text: text || (html ? String(html).replace(/<[^>]+>/g,' ') : ''),
      html: html || `<p>${text || ''}</p>`,
      ...(isVerify ? { trackingSettings: { clickTracking: { enable: false, enableText: false } } } : {})
    };

    for(let i=1;i<=3;i++){
      try{ await withTimeout(sgMail.send(payload), 8000); return true; }
      catch(e){
        console.error(`sendEmail intento ${i} falló:`, e?.message || e, e?.response?.body || '');
        if(i<3) await sleep(600*i);
      }
    }
  }catch(e){ console.error('sendEmail error fatal', e?.message || e); }
  return false;
}


/* ===== Plantillas email ===== */
function _safeName(name){ return (name || '').trim() || null; }
function _emailBaseCss(){
  return `
  :root { color-scheme: light dark; supported-color-schemes: light dark; }
  body{margin:0;background:#0b0f1a;font-family:system-ui,-apple-system,Segoe UI,Inter,Roboto,Arial,sans-serif}
  .wrap{padding:24px}
  .card{max-width:680px;margin:0 auto;background:#0e1424;border:1px solid rgba(255,255,255,.12);border-radius:16px;overflow:hidden}
  /* Header: logo + marca */
  .hdr{padding:22px 24px;display:flex;align-items:center;gap:12px;background:#0b1020}
  .logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(180deg,#7c3aed,#3b82f6)}
  /* Alineamos el texto al centro del logo sin mover nada más */
  .brand{
    font-weight:600;color:#e9eefc;font-size:17px;letter-spacing:.2px;
    display:flex;align-items:center;height:34px;line-height:1; /* <-- clave */
  }
  .body{background:#0e1424;padding:28px 24px 20px;color:#dbe6ff}
  h1{margin:0 0 8px;font-size:36px;line-height:1.1;color:#e9eefc}
  .lead{font-size:18px;line-height:1.5;margin:14px 0 10px;color:#c9d6ff}
  .p{font-size:16px;line-height:1.6;margin:10px 0;color:#c9d6ff}
  .hr{margin:18px 0;border-top:1px solid rgba(255,255,255,.08)}
  .cta{display:inline-block;margin:18px 0 8px;padding:12px 16px;border-radius:10px;background:#7c3aed;color:#fff;text-decoration:none;font-weight:600}
  .foot{border-top:1px solid rgba(255,255,255,.08);padding:16px 24px;color:#a8b4d6;font-size:13px;background:#0b1020}
  @media (max-width:520px){ h1{font-size:30px} .card{border-radius:14px} }
  @media (prefers-color-scheme: light){
    body{background:#f3f6ff}
    .card{background:#ffffff;border:1px solid rgba(2,6,23,.08)}
    .hdr{background:#f7f9ff}
    .body{background:#fff;color:#26324d}
    h1{color:#18213b}
    .lead,.p{color:#394b76}
    .foot{background:#f7f9ff;border-color:rgba(2,6,23,.06);color:#4d5f86}
  }`;
}

function _shell({title, preheader, lead, blocks=[], cta, ctaUrl, brand='Taply'}){
  const b = blocks.map(t=>`<p class="p">${t}</p>`).join('');
  const pre = (preheader||'').replace(/\n/g,' ').slice(0,140);
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title}</title><style>${_emailBaseCss()}</style></head><body>
  <span style="display:none!important;opacity:0;max-height:0;overflow:hidden">${pre}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;</span>
  <div class="wrap"><div class="card">
    <div class="hdr"><div class="logo"></div><div class="brand">${brand}</div></div>
    <div class="body">
      <h1>${title}</h1>
      ${lead?`<div class="lead">${lead}</div>`:''}
      ${b}
      ${cta && ctaUrl ? `<a href="${ctaUrl}" class="cta">${cta}</a>`:''}
      <div class="hr"></div>
      <p class="p" style="font-size:14px;opacity:.85">Este correo se envió automáticamente. Si no reconoces esta acción, respóndenos.</p>
    </div>
  </div></div></body></html>`;
}
function makeSubscriptionEmailUI({name, tierLabel, panelUrl}){
  const title = '¡Suscripción activa!';
  const lead = `Hola${name?` ${name}`:''}, tu suscripción <strong>${tierLabel}</strong> está activa.`;
  const html = _shell({
    title,
    preheader: `Tu suscripción ${tierLabel} ya está activa.`,
    lead,
    blocks: ['Te enviaremos la guía rápida y dejaremos tu panel listo.','¿Dudas? Responde a este correo y te ayudamos.'],
    cta: 'Abrir mi panel',
    ctaUrl: panelUrl || 'https://taply.app/panel'
  });
  return { subject: 'Suscripción activa — Taply', html };
}
function makeNfcEmailUI({name, qty, trackingUrl}){
  const title = '¡Pedido NFC recibido!';
  const lead = `Gracias${name?` ${name}`:''}. Hemos recibido tu pedido correctamente.`;
  const html = _shell({
    title,
    preheader: `Hemos recibido tu pedido de ${qty} NFC.`,
    lead,
    blocks: [`Unidades NFC: <strong>${qty}</strong>`, 'Te contactaremos por WhatsApp con los siguientes pasos.'],
    cta: trackingUrl ? 'Ver estado' : null,
    ctaUrl: trackingUrl || null
  });
  return { subject: '¡Gracias! Hemos recibido tu pedido NFC — Taply', html };
}
function makeVerifyEmailUI({name, verifyUrl}){
  const title = 'Confirma tu correo';
  const lead  = `Hola${name?` ${name}`:''}, confirma tu correo para activar tu cuenta.`;
  const html  = _shell({
    title,
    preheader: 'Confirma tu correo para activar tu cuenta en Taply.',
    lead,
    blocks:['Por tu seguridad, necesitamos verificar que este correo es tuyo.','Haz clic en el botón para activar tu cuenta.'],
    cta: 'Confirmar mi correo',
    ctaUrl: verifyUrl
  });
  return { subject: 'Confirma tu correo — Taply', html };
}

/* ================== Auth ================== */

// POST /api/register
async function register(req, res){
  const { email:rawEmail, password, name } = getBody(req);
  const email = normalizeEmail(rawEmail);

  // Validación de presencia (primero)
  const fieldErrors = {};
  if(!name) fieldErrors.name = 'El nombre es obligatorio.';
  if(!email) fieldErrors.email = 'El correo es obligatorio.';
  if(!password) fieldErrors.password = 'La contraseña es obligatoria.';
  if(Object.keys(fieldErrors).length){
    return res.status(422).json({ error:'validation_error', message:'Revisa los campos obligatorios.', fieldErrors });
  }

  // Buscar email (prioridad errores graves)
  const stripe = getStripe();
  const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit: 1 });
  const exists = found.data[0];

  if(exists){
    const meta = exists.metadata || {};
    const usedByGoogle = (meta.taply_google === '1' || meta.taply_google === 'true');
    const isVerified   = meta.taply_email_verified === '1';
    if(usedByGoogle){
      return res.status(409).json({ error:'email_in_use_google', message:'Este correo ya está vinculado a Google. Inicia sesión con Google.' });
    }
    if(isVerified){
      return res.status(409).json({ error:'email_in_use', message:'Este correo ya está registrado y verificado.' });
    }
    // si existe pero NO verificado -> continuamos (se “resetea”)
  }

  // Fuerza mínima de contraseña (después de comprobar email en uso)
  if(String(password).length < 6){
    return res.status(422).json({ error:'weak_password', message:'La contraseña es demasiado corta (mínimo 6 caracteres).' });
  }

  const hash = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(24).toString('hex');
  const verifyExp   = Math.floor(Date.now()/1000) + EMAIL_VERIFY_TTL_SECONDS;

  if(exists){
    const meta = Object.assign({}, exists.metadata||{}, {
      app:'taply',
      taply_pass_hash: hash,
      taply_nfc_qty: exists.metadata?.taply_nfc_qty || '0',
      taply_google: '0',
      taply_email_verified: '0',
      taply_email_token: verifyToken,
      taply_email_exp: String(verifyExp)
    });
    await stripe.customers.update(exists.id, { name, metadata: meta });
  }else{
    await stripe.customers.create({
      email, name,
      metadata:{
        app:'taply',
        taply_pass_hash: hash,
        taply_nfc_qty:'0',
        taply_google:'0',
        taply_email_verified:'0',
        taply_email_token: verifyToken,
        taply_email_exp: String(verifyExp)
      }
    });
  }

  // Enlace de verificación robusto (con token+email)
  const verifyUrl = `${appBase(req)}/api/verify-email?token=${encodeURIComponent(verifyToken)}&email=${encodeURIComponent(email)}`;
  const tpl = makeVerifyEmailUI({ name, verifyUrl });
  await sendEmail({ to: email, subject: tpl.subject, html: tpl.html });

  return res.status(200).json({ ok:true, confirm_sent:true, message:'Te hemos enviado un correo para confirmar tu cuenta.' });
}

// POST /api/login
async function login(req, res){
  const { email:rawEmail, password } = getBody(req);
  const email = normalizeEmail(rawEmail);

  const fe = {};
  if(!email) fe.email = 'El correo es obligatorio.';
  if(!password) fe.password = 'La contraseña es obligatoria.';
  if(Object.keys(fe).length){
    return res.status(422).json({ error:'validation_error', message:'Revisa los campos obligatorios.', fieldErrors: fe });
  }

  const stripe = getStripe();
  const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit: 1 });
  if(!found.data.length){
    return res.status(404).json({ error:'account_not_found', message:'No encontramos ninguna cuenta con ese correo.' });
  }
  const customer = found.data[0];
  const meta = customer.metadata || {};

  // Si está registrada con Google y no tiene contraseña → mensaje claro
  const usedByGoogle = (meta.taply_google === '1' || meta.taply_google === 'true');
  const hasPass = !!meta.taply_pass_hash;
  if (usedByGoogle && !hasPass) {
    return res.status(409).json({
      error: 'use_google_login',
      message: 'Este correo está registrado con Google. Inicia sesión con Google.'
    });
  }

  // Si NO está verificado, actúa como si no existiera
  if (meta.taply_email_verified !== '1') {
    return res.status(404).json({ error:'account_not_found', message:'No encontramos ninguna cuenta con ese correo.' });
  }

  const hash = meta.taply_pass_hash;
  if(!hash) return res.status(401).json({ error:'password_not_set', message:'Tu cuenta no tiene contraseña establecida.' });

  const ok = await bcrypt.compare(password, hash);
  if(!ok) return res.status(401).json({ error:'invalid_credentials', message:'Correo o contraseña incorrectos.' });

  setSession(res, { email, name: customer.name || null, customerId: customer.id });
  return res.status(200).json({ user:{ email, name: customer.name || null, customerId: customer.id }});
}

/* ===== Google One-tap opcional ===== */
async function googleLogin(req, res){
  const { credential } = getBody(req);
  const clientId = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
  if(!credential){
    return res.status(422).json({ error:'validation_error', message:'Falta el token de Google (credential).' });
  }
  if(!clientId){
    return res.status(500).json({ error:'missing_google_client_id', message:'Falta la configuración de Google.' });
  }

  try{
    const { OAuth2Client } = await import('google-auth-library');
    const g = new OAuth2Client(clientId);
    const ticket = await g.verifyIdToken({ idToken: credential, audience: clientId });
    const payload = ticket.getPayload();
    const email = normalizeEmail(payload?.email || '');
    const emailVerified = !!payload?.email_verified;
    const name = payload?.name || payload?.given_name || null;
    if(!email || !emailVerified) return res.status(401).json({ error:'email_not_verified', message:'Tu correo de Google no está verificado.' });

    const stripe = getStripe();
    const q = `email:'${escapeStripeQueryValue(email)}'`;
    const found = await stripe.customers.search({ query: q, limit: 1 });

    let customerId, finalName = name;
    if(found.data.length){
      const c = found.data[0];
      customerId = c.id; finalName = c.name || name || null;
      const meta = Object.assign({}, c.metadata||{}, { app:'taply', taply_google:'1', taply_nfc_qty: c.metadata?.taply_nfc_qty || '0', taply_email_verified:'1', taply_email_token:'', taply_email_exp:'' });
      try{ await stripe.customers.update(c.id, { name: finalName || undefined, metadata: meta }); }catch{}
    }else{
      const created = await stripe.customers.create({ email, name: name || undefined, metadata: { app:'taply', taply_google:'1', taply_nfc_qty:'0', taply_email_verified:'1' }});
      customerId = created.id; finalName = created.name || name || null;
    }

    setSession(res, { email, name: finalName || null, customerId });
    return res.status(200).json({ user:{ email, name: finalName || null, customerId }});
  }catch(e){
    console.error('googleLogin error', e?.message || e);
    return res.status(401).json({ error:'google_auth_failed', message:'No se pudo validar tu inicio de sesión con Google.' });
  }
}

/* ===== Google OAuth begin/callback (compat) ===== */
async function googleOAuthBegin(req, res){
  const cid = (process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || '').trim();
  if(!cid) return res.status(500).json({ error:'missing_google_client_id', message:'Falta la configuración de Google.' });

  const urlObj = new URL(req.url, 'http://x');
  const from = (urlObj.searchParams.get('from') || 'login').toLowerCase();

  const stateId = crypto.randomBytes(16).toString('hex');
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize('g_state', stateId, {
    httpOnly:true, secure:isProd, sameSite:'lax', path:'/', maxAge:600
  }));

  const redirectUri = `${appBase(req)}/api/google`;
  const state = `${stateId}|${from}`;

  const params = new URLSearchParams({
    response_type: 'code',
    access_type: 'online',
    client_id: cid,
    redirect_uri: redirectUri,
    scope: 'openid email profile',
    include_granted_scopes: 'true',
    prompt: 'select_account',
    state
  });
  res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}` });
  res.end();
}

async function googleOAuthCallback(req, res){
  try{
    const url = new URL(req.url, 'http://x');
    if (url.searchParams.get('__verify') === '1') {
      return verifyEmail(req, res);
    }

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const cookies = getCookies(req);
    const cookieState = cookies['g_state'] || cookies['taply_g_state'] || '';
    if(!code || !state || !cookieState || !state.startsWith(cookieState)) {
      res.writeHead(302, { Location: '/suscripciones.html#google=err&code=state_error' }); return res.end();
    }

    const cid = (process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || '').trim();
    const secret = (process.env.GOOGLE_CLIENT_SECRET || '').trim();
    if(!cid || !secret){
      res.writeHead(302, { Location: '/suscripciones.html#google=err&code=cfg_error' }); return res.end();
    }

    const redirectUri = `${appBase(req)}/api/google`;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: cid, client_secret: secret, grant_type: 'authorization_code', redirect_uri: redirectUri })
    });
    const tokenJson = await tokenRes.json();
    const idToken = tokenJson.id_token;
    if(!idToken) throw new Error('no_id_token');

    const [stateVal, fromState] = String(state || '').split('|');
    const from = (fromState || 'login').toLowerCase();

    const payload = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString('utf8') || '{}');
    const email = normalizeEmail(payload?.email || '');
    const emailVerified = !!payload?.email_verified;
    const name = payload?.name || payload?.given_name || null;
    if(!email || !emailVerified) throw new Error('email_not_verified');

    const stripe = getStripe();
    const q = `email:'${escapeStripeQueryValue(email)}'`;
    const found = await stripe.customers.search({ query: q, limit: 1 });

    let customerId, finalName = name;
    if(found.data.length){
      const c = found.data[0];
      customerId = c.id; finalName = c.name || name || null;
      const meta = Object.assign({}, c.metadata||{}, { app:'taply', taply_google:'1', taply_nfc_qty: c.metadata?.taply_nfc_qty || '0', taply_email_verified:'1', taply_email_token:'', taply_email_exp:'' });
      try{ await stripe.customers.update(c.id, { name: finalName || undefined, metadata: meta }); }catch{}
    }else{
      const created = await stripe.customers.create({ email, name: name || undefined, metadata: { app:'taply', taply_google:'1', taply_nfc_qty:'0', taply_email_verified:'1' }});
      customerId = created.id; finalName = created.name || name || null;
    }

    setSession(res, { email, name: finalName || null, customerId });
    const hashFrom = from === 'register' ? '#google=ok&from=register' : '#google=ok&from=login';
    res.writeHead(302, { Location: `/suscripciones.html${hashFrom}` });
    res.end();
  }catch(e){
    console.error('google-oauth-callback error', e?.message||e);
    res.writeHead(302, { Location: '/suscripciones.html#google=err&code=server_error' }); res.end();
  }
}

/* ===== Verificación de email (acepta token+email o sólo token; GET y POST) ===== */
async function findCustomerByVerifyToken(stripe, token){
  try{
    const q = `metadata['taply_email_token']:'${escapeStripeQueryValue(token)}'`;
    const found = await stripe.customers.search({ query: q, limit: 1 });
    return found.data[0] || null;
  }catch(e){
    console.error('findCustomerByVerifyToken error', e?.message||e);
    return null;
  }
}

async function verifyEmail(req, res){
  try{
    const url = new URL(req.url, 'http://x');
    const body = getBody(req) || {};
    const token = (url.searchParams.get('token') || url.searchParams.get('t') || body.token || '').trim();
    let email   = normalizeEmail(url.searchParams.get('email') || url.searchParams.get('e') || body.email || '');

    if(!token && !email) {
      res.statusCode=400;
      return res.end('Parámetros inválidos.');
    }

    const stripe = getStripe();
    let customer = null;

    // Si tengo email, pruebo por email
    if (email) {
      const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit:1 });
      customer = found.data[0] || null;
    }

    // Si falta email o no encontré, pruebo por token
    if (!customer && token) {
      customer = await findCustomerByVerifyToken(stripe, token);
      if (customer && !email) email = normalizeEmail(customer.email || '');
    }

    // Si no encuentro cliente
    if(!customer){
      return invalidOrExpiredHtml(res, email);
    }

    const exp = Number(customer.metadata?.taply_email_exp || '0');
    const saved = customer.metadata?.taply_email_token || '';

    if (!token || saved !== token || exp < Math.floor(Date.now()/1000)) {
      return invalidOrExpiredHtml(res, email);
    }

    await stripe.customers.update(customer.id, { metadata: { ...(customer.metadata||{}), taply_email_verified:'1', taply_email_token:'', taply_email_exp:'' }});
    setSession(res, { email, name: customer.name || null, customerId: customer.id });

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
    res.setHeader('Content-Type','text/html; charset=utf-8');
    return res.end(html);
  }catch(e){
    console.error('verifyEmail error', e?.message||e);
    res.status(500).end('Error verificando el correo.');
  }
}

function invalidOrExpiredHtml(res, email){
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

/* ===== Reenviar verificación ===== */
async function resendVerification(req, res){
  const email = normalizeEmail(getBody(req).email);
  if(!email) return res.status(422).json({ error:'validation_error', message:'El correo es obligatorio.', fieldErrors:{ email:'El correo es obligatorio.' } });

  try{
    const stripe = getStripe();
    const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit:1 });
    if(!found.data.length) return res.status(200).json({ ok:true, message:'Si el correo existe, enviaremos un enlace de verificación.' });

    const c = found.data[0];
    if (c.metadata?.taply_email_verified === '1') return res.status(200).json({ ok:true, message:'Tu correo ya estaba verificado.' });

    const token = crypto.randomBytes(24).toString('hex');
    const exp   = Math.floor(Date.now()/1000) + EMAIL_VERIFY_TTL_SECONDS;
    await stripe.customers.update(c.id, { metadata: { ...(c.metadata||{}), taply_email_token: token, taply_email_exp: String(exp) }});

    const verifyUrl = `${appBase(req)}/api/verify-email?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
    const tpl = makeVerifyEmailUI({ name: c.name || null, verifyUrl });
    await sendEmail({ to: email, subject: tpl.subject, html: tpl.html });

    return res.status(200).json({ ok:true, message:'Te enviamos un nuevo enlace de verificación.' });
  }catch(e){
    console.error('resendVerification error', e?.message||e);
    return res.status(500).json({ error:'server_error', message:'No pudimos reenviar el correo de verificación.' });
  }
}

/* ===== Portal + Subscriptions + Checkout ===== */
async function getUpcomingPhaseInfo(stripe, sub){
  try{
    if(!sub?.schedule) return null;
    const schedule = await stripe.subscriptionSchedules.retrieve(sub.schedule, { expand: ['phases.items.price'] });
    const now = Math.floor(Date.now()/1000);
    const next = (schedule?.phases || []).find(p => (p.start_date||0) > now) || null;
    if(!next) return null;
    const item = next.items?.[0];
    const price = item?.price;
    return {
      upcoming_start_date: next.start_date || null,
      upcoming_price_id: price?.id || null,
      upcoming_price_nickname: price?.nickname || null
    };
  }catch{ return null; }
}

async function createPortalSession(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });
  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);
  if(!customerId) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });

  const best = await getBestSubscription(stripe, customerId);
  if(!best || !['active','trialing','past_due'].includes(best.status)){
    return res.status(400).json({ error:'no_active_subscription', message:'No tienes ninguna suscripción activa.' });
  }

  try{
    const portal = await stripe.billingPortal.sessions.create({
      customer: customerId, return_url: appBase(req) + '/gestionar.html'
    });
    return res.status(200).json({ url: portal.url });
  }catch(e){
    console.error('createPortalSession error:', e?.message || e);
    return res.status(500).json({ error:'portal_unavailable', message:'El portal de facturación no está disponible.' });
  }
}

async function subscriptionCancel(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });
  const stripe = getStripe();
  const sub = await getBestSubscription(stripe, sess.customerId);
  if(!sub) return res.status(400).json({ error:'no_active_subscription', message:'No tienes ninguna suscripción activa.' });
  const atPeriodEnd = (getBody(req).at_period_end !== false);
  const updated = await stripe.subscriptions.update(sub.id, { cancel_at_period_end: !!atPeriodEnd });
  const normalized = normalizeSub(updated);
  return res.status(200).json({ subscription: normalized, cancel_effective_date: normalized.current_period_end || null });
}
async function subscriptionResume(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });
  const stripe = getStripe();
  const sub = await getBestSubscription(stripe, sess.customerId);
  if(!sub) return res.status(400).json({ error:'no_active_subscription', message:'No tienes ninguna suscripción activa.' });
  const updated = await stripe.subscriptions.update(sub.id, { cancel_at_period_end: false });
  return res.status(200).json({ subscription: normalizeSub(updated) });
}

async function subscriptionSwap(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });
  const { priceId } = getBody(req);
  if(!priceId) return res.status(422).json({ error:'validation_error', message:'Falta el identificador del precio.' });

  const stripe = getStripe();
  const best = await getBestSubscription(stripe, sess.customerId);
  if(!best) return res.status(400).json({ error:'no_active_subscription', message:'No tienes ninguna suscripción activa.' });
  const sub = await stripe.subscriptions.retrieve(best.id, { expand: ['items.data.price','schedule'] });

  const currentItems = sub.items.data.map(it => ({ price: it.price.id, quantity: it.quantity || 1 }));

  try{
    if (sub.schedule) {
      const phases = [
        { start_date: 'now', end_date: sub.current_period_end, items: currentItems, proration_behavior: 'none' },
        { start_date: sub.current_period_end, items: [{ price: priceId, quantity: 1 }], proration_behavior: 'none' }
      ];
      await stripe.subscriptionSchedules.update(sub.schedule, { phases });
    } else {
      await stripe.subscriptionSchedules.create({
        from_subscription: sub.id,
        phases: [
          { start_date: 'now', end_date: sub.current_period_end, items: currentItems, proration_behavior: 'none' },
          { start_date: sub.current_period_end, items: [{ price: priceId, quantity: 1 }], proration_behavior: 'none' }
        ],
        metadata: { app:'taply', change:'swap_at_period_end' }
      });
    }

    const updated = await stripe.subscriptions.retrieve(sub.id, { expand:['items.data.price'] });
    const nextInfo = await getUpcomingPhaseInfo(stripe, updated);
    return res.status(200).json({ subscription: normalizeSub(updated), scheduled_change: nextInfo || null });
  }catch(e){
    console.error('subscriptionSwap schedule error', e?.message || e);
    return res.status(500).json({ error:'swap_failed', message:'No pudimos programar el cambio de plan.' });
  }
}

async function createCheckoutSession(req, res){
  const { tier, frequency } = getBody(req);
  if (!tier || !frequency) return res.status(422).json({ error:'validation_error', message:'Faltan parámetros de plan.' });
  const price = PRICES?.[frequency]?.[tier];
  if (!price) return res.status(400).json({ error: 'price_not_found', message:'No encontramos el precio seleccionado.' });

  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error: 'auth_required', message:'Debes iniciar sesión.' });

  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);

  const already = await hasValidSubscription(stripe, customerId);
  if (already) {
    const best = await getBestSubscription(stripe, customerId);
    const sub = normalizeSub(best);
    return res.status(409).json({ error: 'already_subscribed', message:'Ya tienes una suscripción activa.', current: sub });
  }

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    ui_mode: 'hosted',
    line_items: [{ price, quantity: 1 }],
    allow_promotion_codes: true,
    success_url: `${appBase(req)}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appBase(req)}/cancelado.html`,
    phone_number_collection: { enabled: true },
    customer: customerId,
    subscription_data: { metadata: { type: 'subscription', tier, frequency, app:'taply' } },
    metadata: { type: 'subscription', tier, frequency, app:'taply' }
  });

  if (!session?.url) return res.status(500).json({ error: 'no_session_url', message:'No pudimos iniciar el pago.' });
  return res.status(200).json({ url: session.url });
}

async function buyNfc(req, res){
  if (!PRICE_ID_NFC) return res.status(500).json({ error: 'missing_nfc_price_id', message:'Falta configurar el precio NFC.' });
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error: 'auth_required', message:'Debes iniciar sesión.' });
  const { quantity = 1 } = getBody(req);
  const qty = Math.max(1, Math.min(Number(quantity) || 1, 999));
  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);
  if(!customerId) return res.status(401).json({ error:'auth_required', message:'Debes iniciar sesión.' });

  const session = await stripe.checkout.sessions.create({
    mode: 'payment', ui_mode: 'hosted',
    line_items: [{ price: PRICE_ID_NFC, quantity: qty }],
    success_url: `${appBase(req)}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appBase(req)}/cancelado.html`,
    allow_promotion_codes: true,
    phone_number_collection: { enabled: true },
    billing_address_collection: 'auto',
    shipping_address_collection: { allowed_countries: ['ES'] },
    metadata: { type: 'nfc', qty: String(qty), app:'taply' },
    customer: customerId
  });
  if (!session?.url) return res.status(500).json({ error: 'no_session_url', message:'No pudimos iniciar el pago.' });
  return res.status(200).json({ url: session.url });
}

/* ===== Post-pago ===== */
async function postPago(req, res){
  const stripe = getStripe();
  const url = new URL(req.url, 'http://x');
  const qpSession = url.searchParams.get('session_id');
  const { session_id: bodySession, type } = getBody(req);
  const sessionId = bodySession || qpSession || null;

  let buyerEmail = null, buyerPhone = null, lineSummary = '', amountText = '', customerId = null;
  let cs = null;

  if(sessionId){
    try{
      cs = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items','customer_details'] });
      buyerEmail = cs.customer_details?.email || cs.customer_email || null;
      buyerPhone = cs.customer_details?.phone || null;
      customerId = typeof cs.customer === 'string' ? cs.customer : cs.customer?.id || null;
      const li = cs.line_items?.data || [];
      lineSummary = li.map(i => `${i.quantity} × ${i.description || i.price?.nickname || i.price?.id}`).join(', ');
      amountText = (cs.amount_total!=null && cs.currency) ? `${(cs.amount_total/100).toFixed(2)} ${cs.currency.toUpperCase()}` : '';

      if (cs.mode === 'payment' && PRICE_ID_NFC && customerId) {
        const addQty = li.reduce((acc, it) => acc + ((it.price?.id === PRICE_ID_NFC) ? (it.quantity || 0) : 0), 0);
        if(addQty > 0){
          const cust = await stripe.customers.retrieve(customerId);
          const prev = parseInt(cust?.metadata?.taply_nfc_qty || '0', 10) || 0;
          await stripe.customers.update(customerId, { metadata: { ...(cust.metadata||{}), taply_nfc_qty: String(prev + addQty) }});
        }
      }
    }catch(e){ console.error('post-pago retrieve error', e?.message || e); }
  }

  if(!buyerEmail && customerId){
    try{
      const cust = await stripe.customers.retrieve(customerId);
      buyerEmail = cust?.email || null;
      if(!buyerPhone) buyerPhone = cust?.phone || null;
    }catch{}
  }

  const sess = getSessionFromCookie(req);
  if(!buyerEmail && sess?.email) buyerEmail = sess.email;

  if(buyerEmail){
    try{
      if (cs?.mode === 'subscription') {
        const item = cs?.line_items?.data?.[0];
        const tierNickname = item?.price?.nickname || item?.description || 'Taply';
        const name = _safeName(cs?.customer_details?.name);
        const tpl = makeSubscriptionEmailUI({ name, tierLabel: tierNickname, panelUrl: appBase(req) + '/panel.html' });
        const ok = await sendEmail({ to: buyerEmail, subject: tpl.subject, html: tpl.html });
        if(!ok){ await sendEmail({ to: buyerEmail, subject: 'Suscripción activa — Taply', html: `<h2>¡Gracias!</h2><p>Tu suscripción está activa.</p>` }); }
      } else {
        const qtyNfc = (cs?.line_items?.data || []).reduce((acc,i)=> acc + (i.price?.id === PRICE_ID_NFC ? (i.quantity||0) : 0), 0) || 1;
        const name = _safeName(cs?.customer_details?.name);
        const tpl = makeNfcEmailUI({ name, qty: qtyNfc });
        const ok = await sendEmail({ to: buyerEmail, subject: tpl.subject, html: tpl.html });
        if(!ok){ await sendEmail({ to: buyerEmail, subject: 'Pedido recibido — Taply', html: `<h2>¡Gracias!</h2><p>Hemos recibido tu pedido NFC.</p>` }); }
      }
    }catch(e){
      console.error('send designed email failed, falling back', e?.message || e);
      const subj = '¡Gracias! Hemos recibido tu compra';
      const html = `<h2>Gracias por tu compra en Taply</h2>
        <p>Hemos recibido tu ${type || 'pedido'} correctamente.</p>
        ${lineSummary ? `<p><strong>Productos:</strong> ${lineSummary}</p>` : ''}
        ${amountText ? `<p><strong>Importe:</strong> ${amountText}</p>` : ''}
        <p>Te contactaremos por WhatsApp con los siguientes pasos.</p>`;
      await sendEmail({ to: buyerEmail, subject: subj, html });
    }
  }

  if(process.env.EMAIL_FROM){
    const subjAdm = 'Nueva compra recibida';
    const htmlAdm = `
      <p>Compra recibida (${type || cs?.mode || 'checkout'}).</p>
      ${buyerEmail ? `<p>Email cliente: ${buyerEmail}</p>` : ''}
      ${buyerPhone ? `<p>Teléfono cliente: ${buyerPhone}</p>` : ''}
      ${lineSummary ? `<p>Line items: ${lineSummary}</p>` : ''}
      ${amountText ? `<p>Importe: ${amountText}</p>` : ''}
      ${sessionId ? `<p>Checkout Session: ${sessionId}</p>` : ''}
    `;
    await sendEmail({ to: parseAddress(process.env.EMAIL_FROM).email, subject: subjAdm, html: htmlAdm });

  }

  return res.status(200).json({ ok:true });
}

async function storeCustomerFromSession(req, res){
  const { session_id } = getBody(req);
  if(!session_id) return res.status(422).json({ error:'validation_error', message:'Falta session_id.' });

  try{
    const stripe = getStripe();
    const cs = await stripe.checkout.sessions.retrieve(session_id, { expand:['customer','customer_details'] });
    const custObj = (typeof cs.customer === 'string') ? await stripe.customers.retrieve(cs.customer) : cs.customer;
    const customerId = custObj?.id || null;
    const email = cs.customer_details?.email || cs.customer_email || custObj?.email || null;
    const name  = cs.customer_details?.name  || custObj?.name  || null;
    if(!customerId || !email) return res.status(400).json({ error:'no_customer_in_session', message:'No pudimos obtener los datos del cliente.' });

    if(name && custObj && !custObj.name){ try{ await stripe.customers.update(customerId, { name }); }catch{} }
    setSession(res, { email, name: name || null, customerId });
    return res.status(200).json({ user: { email, name: name || null, customerId }});
  }catch(e){
    console.error('storeCustomerFromSession error', e?.message || e);
    return res.status(500).json({ error:'server_error', message:'No pudimos guardar tu sesión.' });
  }
}

/* ===== Session ===== */
async function session(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(200).json({ user:null });

  const stripe = getStripe();

  let nfcQty = 0, customer = null;
  try {
    customer = await stripe.customers.retrieve(sess.customerId);
    nfcQty = parseInt(customer?.metadata?.taply_nfc_qty || '0', 10) || 0;
  } catch {
    return res.status(200).json({ user: { email: sess.email, name: sess.name || null, customerId: null, subscription: null, subscription_status: null, nfc_qty: 0 }});
  }

  const best = await getBestSubscription(stripe, sess.customerId);
  const sub = normalizeSub(best);

  let nextGuess = null;
  if (sub?.current_period_start) {
    const start = new Date(sub.current_period_start * 1000);
    nextGuess = (sub.price?.interval === 'year')
      ? new Date(start.getFullYear()+1, start.getMonth(), start.getDate()).getTime()/1000
      : Math.floor(addDays(start, 30).getTime()/1000);
  } else if (sub?.current_period_end) {
    nextGuess = sub.current_period_end;
  }

  const upcoming = await getUpcomingPhaseInfo(getStripe(), best);

  return res.status(200).json({
    user: {
      email: sess.email,
      name: sess.name || (customer?.name || null),
      customerId: sess.customerId,
      subscription: sub,
      subscription_status: sub?.status || null,
      current_period_end: sub?.current_period_end || null,
      current_period_start: sub?.current_period_start || null,
      nfc_qty: nfcQty,
      next_period_anchor_guess: nextGuess,
      cancel_effective_date: sub?.cancel_at_period_end ? (sub?.current_period_end || nextGuess || null) : null,
      scheduled_change: upcoming ? {
        upcoming_price_id: upcoming.upcoming_price_id || null,
        upcoming_price_nickname: upcoming.upcoming_price_nickname || null,
        upcoming_start_date: upcoming.upcoming_start_date || null
      } : null,
      upcoming_price_id: upcoming?.upcoming_price_id || null,
      upcoming_price_nickname: upcoming?.upcoming_price_nickname || null,
      upcoming_start_date: upcoming?.upcoming_start_date || null
    }
  });
}

/* ===== Router ===== */
export default async function handler(req, res){
  try{
    assertEnv();
    const route = routeOf(req);

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      return res.status(204).end();
    }

    if (req.method === 'GET') {
      if (route === 'session') return session(req,res);
      if (route === 'google-oauth-begin') return googleOAuthBegin(req,res);
      if (route === 'google-oauth-callback') return googleOAuthCallback(req,res);

      if (route === 'google') {
        const u = new URL(req.url, 'http://x');
        if (u.searchParams.get('__verify') === '1') {
          return verifyEmail(req,res);
        }
        return googleOAuthCallback(req,res);
      }

      if (route === 'verify-email') return verifyEmail(req,res);
    }

    if (req.method === 'POST') {
      if (route === 'register') return register(req,res);
      if (route === 'login') return login(req,res);
      if (route === 'google-login') return googleLogin(req,res);

      if (route === 'logout') { clearSession(res); return res.status(200).json({ ok:true, message:'Sesión cerrada.' }); }
      if (route === 'request-password-reset') return requestPasswordReset(req,res);
      if (route === 'reset-password') return resetPassword(req,res);

      if (route === 'create-portal-session' || route === 'portal' || route === 'create-billing-portal')
        return createPortalSession(req,res);

      if (route === 'subscription/cancel') return subscriptionCancel(req,res);
      if (route === 'subscription/resume') return subscriptionResume(req,res);
      if (route === 'subscription/swap')   return subscriptionSwap(req,res);

      if (route === 'create-checkout-session') return createCheckoutSession(req,res);
      if (route === 'buy-nfc') return buyNfc(req,res);

      if (route === 'post-pago') return postPago(req,res);
      if (route === 'store-customer-from-session') return storeCustomerFromSession(req,res);

      if (route === 'resend-verification') return resendVerification(req,res);
      if (route === 'verify-email') return verifyEmail(req,res); // <-- permite POST también
    }

    return res.status(404).json({ error:'not_found', message:'Ruta no encontrada.', route, method:req.method });
  }catch(e){
    const code = e?.statusCode || 500;
    console.error('api error', e);
    return res.status(code).json({ error:'server_error', message:'Error interno del servidor.', detail: e?.message || String(e) });
  }
}

/* ===== Recuperación contraseña ===== */
async function requestPasswordReset(req, res){
  const email = normalizeEmail(getBody(req).email);
  if(!email) return res.status(422).json({ error:'validation_error', message:'El correo es obligatorio.', fieldErrors:{ email:'El correo es obligatorio.' } });

  const stripe = getStripe();
  const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit: 1 });
  if(!found.data.length) return res.status(200).json({ ok:true, message:'Si el correo existe, te enviaremos un enlace.' });

  const customer = found.data[0];
  const token = crypto.randomBytes(24).toString('hex');
  const exp = Math.floor(Date.now()/1000) + RESET_TTL_SECONDS;

  await stripe.customers.update(customer.id, {
    metadata: { ...(customer.metadata||{}), taply_reset_token: token, taply_reset_exp: String(exp) }
  });

  const link = `${appBase(req)}/reset.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
  await sendEmail({
    to: email,
    subject: 'Recupera tu contraseña — Taply',
    html: `<p>Para restablecer tu contraseña haz clic en el botón:</p>
           <p><a href="${link}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:#7c3aed;color:#fff;text-decoration:none">Establecer nueva contraseña</a></p>
           <p>Este enlace caduca en 1 hora.</p>`
  });

  return res.status(200).json({ ok:true, message:'Si el correo existe, te enviaremos un enlace.' });
}

async function resetPassword(req, res){
  const email = normalizeEmail(getBody(req).email);
  const { token, password } = getBody(req);
  const fe = {};
  if(!email) fe.email = 'El correo es obligatorio.';
  if(!token) fe.token = 'Falta el token.';
  if(!password) fe.password = 'La contraseña es obligatoria.';
  if(Object.keys(fe).length) return res.status(422).json({ error:'validation_error', message:'Revisa los campos.', fieldErrors: fe });
  if(password.length < 6) return res.status(422).json({ error:'weak_password', message:'La contraseña es demasiado corta (mínimo 6 caracteres).' });

  const stripe = getStripe();
  const found = await stripe.customers.search({ query: `email:'${escapeStripeQueryValue(email)}'`, limit: 1 });
  if(!found.data.length) return res.status(400).json({ error:'invalid_token', message:'Token inválido.' });

  const customer = found.data[0];
  const meta = customer.metadata || {};
  const saved = meta.taply_reset_token;
  const exp = Number(meta.taply_reset_exp || '0');

  if(!saved || saved !== token || exp < Math.floor(Date.now()/1000)){
    return res.status(400).json({ error:'invalid_or_expired_token', message:'El enlace no es válido o ha caducado.' });
  }

  const hash = await bcrypt.hash(password, 10);
  await stripe.customers.update(customer.id, { metadata: { ...meta, taply_pass_hash: hash, taply_reset_token: '', taply_reset_exp: '' }});
  return res.status(200).json({ ok:true, message:'Contraseña actualizada.' });
}
