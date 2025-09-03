// api/[...taply].js
import Stripe from 'stripe';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import crypto from 'node:crypto';

const COOKIE_NAME = 'taply_session';
const RESET_TTL_SECONDS = 60 * 60; // 1 hora

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

/* ============ Utils base ============ */
function assertEnv() {
  if (!process.env.APP_SECRET) throw Object.assign(new Error('missing APP_SECRET'), { statusCode: 500 });
  if (!process.env.STRIPE_SECRET_KEY) throw Object.assign(new Error('missing STRIPE_SECRET_KEY'), { statusCode: 500 });
}
function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}
function appBase(req){
  return process.env.APP_BASE_URL || process.env.BASE_URL || baseUrl(req);
}
function getBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body); } catch { return {}; }
}
function getCookies(req){
  try { return cookie.parse(req.headers.cookie || ''); } catch { return {}; }
}
function normalizeEmail(email=''){ return String(email).trim().toLowerCase(); }
function setSession(res, payload){
  const token = jwt.sign(payload, process.env.APP_SECRET, { expiresIn: '90d' });
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, token, {
    httpOnly:true, secure:isProd, sameSite:'lax', path:'/', maxAge:60*60*24*90
  }));
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

/* ============ Stripe helpers ============ */
let stripeSingleton = null;
function getStripe(){
  if (!stripeSingleton) {
    stripeSingleton = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
  }
  return stripeSingleton;
}
// Evita inyección en customers.search
function escapeStripeQueryValue(v=''){
  return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
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
    price: { id: price?.id || null, nickname: price?.nickname || null, interval: interval || null }
  };
}
async function getBestSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({
    customer: customerId,
    status: 'all',
    expand: ['data.items.data.price']
  });
  const order = { active:3, trialing:2, past_due:1 };
  const best = subs.data.sort((a,b)=> (order[b.status]||0)-(order[a.status]||0) || (b.current_period_end||0)-(a.current_period_end||0))[0];
  return best || null;
}
async function hasValidSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
  return subs.data.some(s => ['active','trialing','past_due'].includes(s.status));
}

/* ===== util fechas: mensual = 30 días exactos (tu requerimiento) ===== */
function addDays(d, days){ return new Date(d.getTime() + days*24*60*60*1000); }

/* ========= Envíos opcionales ========= */
async function sendEmail({to, subject, text, html}){
  try{
    if(!process.env.SENDGRID_API_KEY || !process.env.EMAIL_FROM) return;
    const { default: sgMail } = await import('@sendgrid/mail');
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    await sgMail.send({
      to,
      from: process.env.EMAIL_FROM,
      replyTo: process.env.EMAIL_REPLY_TO || process.env.EMAIL_FROM,
      subject,
      text: text || (html ? html.replace(/<[^>]+>/g,' ') : ''),
      html: html || `<p>${text || ''}</p>`
    });
  }catch(e){ console.error('sendEmail error', e); }
}

/* ================== Handlers ================== */

// POST /api/register  (bloquea email duplicado)
async function register(req, res){
  const rawEmail = getBody(req).email;
  const email = normalizeEmail(rawEmail);
  const { password, name } = getBody(req);
  if(!email || !password || !name) return res.status(400).json({ error:'name_email_password_required' });
  if(password.length < 6) return res.status(400).json({ error:'weak_password' });

  const stripe = getStripe();
  const q = `email:'${escapeStripeQueryValue(email)}'`;
  const found = await stripe.customers.search({ query: q, limit: 1 });

  if(found.data.length){
    return res.status(409).json({ error:'email_in_use' });
  }

  const hash = await bcrypt.hash(password, 10);
  const customer = await stripe.customers.create({
    email, name,
    metadata:{ app:'taply', taply_pass_hash: hash, taply_nfc_qty: '0' }
  });
  setSession(res, { email, name, customerId: customer.id });
  return res.status(200).json({ user:{ email, name, customerId: customer.id }});
}

// POST /api/login
async function login(req, res){
  const rawEmail = getBody(req).email;
  const email = normalizeEmail(rawEmail);
  const { password } = getBody(req);
  if(!email || !password) return res.status(400).json({ error:'email_and_password_required' });
  const stripe = getStripe();
  const q = `email:'${escapeStripeQueryValue(email)}'`;
  const found = await stripe.customers.search({ query: q, limit: 1 });
  if(!found.data.length) return res.status(401).json({ error:'account_not_found' });
  const customer = found.data[0];
  const hash = customer.metadata?.taply_pass_hash;
  if(!hash) return res.status(401).json({ error:'password_not_set' });
  const ok = await bcrypt.compare(password, hash);
  if(!ok) return res.status(401).json({ error:'invalid_credentials' });
  setSession(res, { email, name: customer.name || null, customerId: customer.id });
  return res.status(200).json({ user:{ email, name: customer.name || null, customerId: customer.id }});
}

// POST /api/logout
async function logout(_req, res){ clearSession(res); return res.status(200).json({ ok:true }); }

// GET /api/session
async function session(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(200).json({ user:null });

  const stripe = getStripe();

  // Customer y NFC
  let nfcQty = 0, customer = null;
  try {
    customer = await stripe.customers.retrieve(sess.customerId);
    nfcQty = parseInt(customer?.metadata?.taply_nfc_qty || '0', 10) || 0;
  } catch {
    return res.status(200).json({ user: { email: sess.email, name: sess.name || null, customerId: null, subscription: null, subscription_status: null, nfc_qty: 0 }});
  }

  // Suscripción
  const best = await getBestSubscription(stripe, sess.customerId);
  const sub = normalizeSub(best);

  // Próxima “renovación” aparente
  let nextGuess = null;
  if (sub?.current_period_start) {
    const start = new Date(sub.current_period_start * 1000);
    nextGuess = (sub.price?.interval === 'year')
      ? new Date(start.getFullYear()+1, start.getMonth(), start.getDate()).getTime()/1000
      : Math.floor(addDays(start, 30).getTime()/1000);
  } else if (sub?.current_period_end) {
    nextGuess = sub.current_period_end;
  }

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
      next_period_anchor_guess: nextGuess
    }
  });
}

/* ======== Recuperación de contraseña ======== */
async function requestPasswordReset(req, res){
  const email = normalizeEmail(getBody(req).email);
  if(!email) return res.status(400).json({ error:'email_required' });

  const stripe = getStripe();
  const q = `email:'${escapeStripeQueryValue(email)}'`;
  const found = await stripe.customers.search({ query: q, limit: 1 });
  if(!found.data.length) return res.status(200).json({ ok:true });

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
    html: `<p>Para restablecer tu contraseña, haz clic:</p>
           <p><a href="${link}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:#7c3aed;color:#fff;text-decoration:none">Establecer nueva contraseña</a></p>
           <p>Este enlace caduca en 1 hora.</p>`
  });

  return res.status(200).json({ ok:true });
}
async function resetPassword(req, res){
  const email = normalizeEmail(getBody(req).email);
  const { token, password } = getBody(req);
  if(!email || !token || !password) return res.status(400).json({ error:'missing_params' });
  if(password.length < 6) return res.status(400).json({ error:'weak_password' });

  const stripe = getStripe();
  const q = `email:'${escapeStripeQueryValue(email)}'`;
  const found = await stripe.customers.search({ query: q, limit: 1 });
  if(!found.data.length) return res.status(400).json({ error:'invalid_token' });

  const customer = found.data[0];
  const meta = customer.metadata || {};
  const saved = meta.taply_reset_token;
  const exp = Number(meta.taply_reset_exp || '0');

  if(!saved || saved !== token || exp < Math.floor(Date.now()/1000)){
    return res.status(400).json({ error:'invalid_or_expired_token' });
  }

  const hash = await bcrypt.hash(password, 10);
  await stripe.customers.update(customer.id, { metadata: { ...meta, taply_pass_hash: hash, taply_reset_token: '', taply_reset_exp: '' }});
  return res.status(200).json({ ok:true });
}

/* ======== Portal de facturación ======== */
// POST /api/create-portal-session (+ alias /api/portal y /api/create-billing-portal)
async function createPortalSession(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required' });
  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);
  if(!customerId) return res.status(401).json({ error:'auth_required' });

  try{
    const portal = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: appBase(req) + '/gestionar.html'
    });
    return res.status(200).json({ url: portal.url });
  }catch(e){
    console.error('createPortalSession error:', e?.message || e);
    return res.status(500).json({ error:'portal_unavailable' });
  }
}

/* ======== Suscripciones: cancelar / reanudar / cambiar plan ======== */
// POST /api/subscription/cancel  { at_period_end?: boolean }
async function subscriptionCancel(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required' });

  const stripe = getStripe();
  const sub = await getBestSubscription(stripe, sess.customerId);
  if(!sub) return res.status(400).json({ error:'no_active_subscription' });

  const atPeriodEnd = (getBody(req).at_period_end !== false); // por defecto: true
  const updated = await stripe.subscriptions.update(sub.id, { cancel_at_period_end: !!atPeriodEnd });
  return res.status(200).json({ subscription: normalizeSub(updated) });
}

// POST /api/subscription/resume
async function subscriptionResume(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required' });

  const stripe = getStripe();
  const sub = await getBestSubscription(stripe, sess.customerId);
  if(!sub) return res.status(400).json({ error:'no_active_subscription' });

  const updated = await stripe.subscriptions.update(sub.id, { cancel_at_period_end: false });
  return res.status(200).json({ subscription: normalizeSub(updated) });
}

// POST /api/subscription/swap { priceId }
async function subscriptionSwap(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error:'auth_required' });

  const { priceId } = getBody(req);
  if(!priceId) return res.status(400).json({ error:'missing_params' });

  const stripe = getStripe();
  const sub = await getBestSubscription(stripe, sess.customerId);
  if(!sub) return res.status(400).json({ error:'no_active_subscription' });

  const currentItemId = sub.items.data[0].id;
  const updated = await stripe.subscriptions.update(sub.id, {
    items: [{ id: currentItemId, price: priceId }],
    proration_behavior: 'create_prorations'
  });

  return res.status(200).json({ subscription: normalizeSub(updated) });
}

/* ======== Checkout ======== */
// POST /api/create-checkout-session  (suscripciones)
async function createCheckoutSession(req, res){
  const { tier, frequency } = getBody(req);
  if (!tier || !frequency) return res.status(400).json({ error: 'missing_params' });

  const price = PRICES?.[frequency]?.[tier];
  if (!price) return res.status(400).json({ error: 'price_not_found' });

  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error: 'auth_required' });

  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);

  const already = await hasValidSubscription(stripe, customerId);
  if (already) {
    const best = await getBestSubscription(stripe, customerId);
    const sub = normalizeSub(best);
    return res.status(409).json({ error: 'already_subscribed', current: sub });
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
    subscription_data: {
      metadata: { type: 'subscription', tier, frequency, app:'taply' }
    },
    metadata: { type: 'subscription', tier, frequency, app:'taply' }
  });

  if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
  return res.status(200).json({ url: session.url });
}

// POST /api/buy-nfc  (pago único)
async function buyNfc(req, res){
  if (!PRICE_ID_NFC) return res.status(500).json({ error: 'missing_nfc_price_id' });

  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error: 'auth_required' });

  const { quantity = 1 } = getBody(req);
  const qty = Math.max(1, Math.min(Number(quantity) || 1, 999));

  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);
  if(!customerId) return res.status(401).json({ error:'auth_required' });

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    ui_mode: 'hosted',
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

  if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
  return res.status(200).json({ url: session.url });
}

/* ========= POST /api/post-pago (fallback por si el webhook no corre) ========= */
async function postPago(req, res){
  const stripe = getStripe();
  const url = new URL(req.url, 'http://x');
  const qpSession = url.searchParams.get('session_id');
  const { session_id: bodySession, type } = getBody(req);
  const sessionId = bodySession || qpSession || null;

  let buyerEmail = null, buyerPhone = null, lineSummary = '', amountText = '', customerId = null;

  if(sessionId){
    try{
      const cs = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items','customer_details'] });
      buyerEmail = cs.customer_details?.email || null;
      buyerPhone = cs.customer_details?.phone || null;
      customerId = typeof cs.customer === 'string' ? cs.customer : cs.customer?.id || null;
      const li = cs.line_items?.data || [];
      lineSummary = li.map(i => `${i.quantity} × ${i.description || i.price?.nickname || i.price?.id}`).join(', ');
      amountText = (cs.amount_total!=null && cs.currency) ? `${(cs.amount_total/100).toFixed(2)} ${cs.currency.toUpperCase()}` : '';

      // Fallback: sumar NFC aquí también
      if (cs.mode === 'payment' && PRICE_ID_NFC && customerId) {
        const addQty = li.reduce((acc, it) => acc + ((it.price?.id === PRICE_ID_NFC) ? (it.quantity || 0) : 0), 0);
        if(addQty > 0){
          const cust = await stripe.customers.retrieve(customerId);
          const prev = parseInt(cust?.metadata?.taply_nfc_qty || '0', 10) || 0;
          await stripe.customers.update(customerId, { metadata: { ...(cust.metadata||{}), taply_nfc_qty: String(prev + addQty) }});
        }
      }
    }catch(e){
      console.error('post-pago retrieve error', e?.message || e);
    }
  }

  const sess = getSessionFromCookie(req);
  if(!buyerEmail && sess?.email) buyerEmail = sess.email;

  if(buyerEmail){
    const subj = '¡Gracias! Hemos recibido tu compra';
    const html = `
      <h2>Gracias por tu compra en Taply</h2>
      <p>Hemos recibido tu ${type || 'pedido'} correctamente.</p>
      ${lineSummary ? `<p><strong>Productos:</strong> ${lineSummary}</p>` : ''}
      ${amountText ? `<p><strong>Importe:</strong> ${amountText}</p>` : ''}
      <p>Te contactaremos por WhatsApp con los siguientes pasos.</p>
    `;
    await sendEmail({ to: buyerEmail, subject: subj, html });
  }

  if(process.env.EMAIL_FROM){
    const subjAdm = 'Nueva compra recibida';
    const htmlAdm = `
      <p>Compra recibida (${type || 'checkout'}).</p>
      ${buyerEmail ? `<p>Email cliente: ${buyerEmail}</p>` : ''}
      ${buyerPhone ? `<p>Teléfono cliente: ${buyerPhone}</p>` : ''}
      ${lineSummary ? `<p>Line items: ${lineSummary}</p>` : ''}
      ${amountText ? `<p>Importe: ${amountText}</p>` : ''}
      ${sessionId ? `<p>Checkout Session: ${sessionId}</p>` : ''}
    `;
    await sendEmail({ to: process.env.EMAIL_FROM, subject: subjAdm, html: htmlAdm });
  }

  return res.status(200).json({ ok:true });
}

/* ======== POST /api/store-customer-from-session ========= */
async function storeCustomerFromSession(req, res){
  const { session_id } = getBody(req);
  if(!session_id) return res.status(400).json({ error:'missing_params' });

  try{
    const stripe = getStripe();
    const cs = await stripe.checkout.sessions.retrieve(session_id, { expand:['customer','customer_details'] });

    const custObj = (typeof cs.customer === 'string') ? await stripe.customers.retrieve(cs.customer) : cs.customer;
    const customerId = custObj?.id || null;
    const email = cs.customer_details?.email || custObj?.email || null;
    const name  = cs.customer_details?.name  || custObj?.name  || null;

    if(!customerId || !email){
      return res.status(400).json({ error:'no_customer_in_session' });
    }

    if(name && custObj && !custObj.name){
      try{ await stripe.customers.update(customerId, { name }); }catch{}
    }

    setSession(res, { email, name: name || null, customerId });

    return res.status(200).json({ user: { email, name: name || null, customerId }});
  }catch(e){
    console.error('storeCustomerFromSession error', e?.message || e);
    return res.status(500).json({ error:'server_error' });
  }
}

/* ======== Google Login (token one-tap) ======== */
async function googleLogin(req, res){
  const { credential } = getBody(req) || {};
  if(!credential) return res.status(400).json({ error:'missing_params' });
  const clientId = process.env.GOOGLE_OAUTH_CLIENT_ID;
  if(!clientId) return res.status(500).json({ error:'missing_google_client_id' });

  try{
    const { OAuth2Client } = await import('google-auth-library');
    const client = new OAuth2Client(clientId);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: clientId });
    const payload = ticket.getPayload();
    const email = normalizeEmail(payload?.email || '');
    const name = payload?.name || payload?.given_name || null;
    if(!email) return res.status(400).json({ error:'google_email_required' });

    const stripe = getStripe();
    const q = `email:'${escapeStripeQueryValue(email)}'`;
    const found = await stripe.customers.search({ query: q, limit: 1 });

    let customerId;
    if(found.data.length){
      customerId = found.data[0].id;
      if(name && !found.data[0].name){
        try{ await stripe.customers.update(customerId, { name }); }catch{}
      }
    }else{
      const created = await stripe.customers.create({
        email, name: name || undefined,
        metadata: { app:'taply', provider:'google', taply_nfc_qty: '0' }
      });
      customerId = created.id;
    }

    setSession(res, { email, name: name || null, customerId });
    return res.status(200).json({ user: { email, name: name || null, customerId } });
  }catch(e){
    console.error('googleLogin error', e?.message || e);
    return res.status(401).json({ error:'google_auth_failed' });
  }
}

/* ================== Router ================== */
export default async function handler(req, res){
  try{
    assertEnv();
    const route = routeOf(req);

    // Preflight muy básico
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      return res.status(204).end();
    }

    if (req.method === 'GET' && route === 'session') return session(req,res);

    if (req.method === 'POST') {
      if (route === 'register') return register(req,res);
      if (route === 'login') return login(req,res);
      if (route === 'logout') return logout(req,res);
      if (route === 'request-password-reset') return requestPasswordReset(req,res);
      if (route === 'reset-password') return resetPassword(req,res);
      if (route === 'google-login') return googleLogin(req,res); // <-- Google

      // Portal (alias válidos)
      if (route === 'create-portal-session' || route === 'portal' || route === 'create-billing-portal')
        return createPortalSession(req,res);

      // Suscripción
      if (route === 'subscription/cancel') return subscriptionCancel(req,res);
      if (route === 'subscription/resume') return subscriptionResume(req,res);
      if (route === 'subscription/swap')   return subscriptionSwap(req,res);

      // Checkout
      if (route === 'create-checkout-session') return createCheckoutSession(req,res);
      if (route === 'buy-nfc') return buyNfc(req,res);

      // Post-pago (fallback) + compat
      if (route === 'post-pago') return postPago(req,res);
      if (route === 'store-customer-from-session') return storeCustomerFromSession(req,res);
    }

    return res.status(404).json({ error:'not_found', route, method:req.method });
  }catch(e){
    const code = e?.statusCode || 500;
    console.error('api error', e);
    return res.status(code).json({ error:'server_error', detail: e?.message || String(e) });
  }
}
