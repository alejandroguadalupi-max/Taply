// api/[...taply].js
import Stripe from 'stripe';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

const COOKIE_NAME = 'taply_session';

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
  return (typeof req.body === 'string') ? JSON.parse(req.body) : req.body;
}
function getCookies(req){
  try { return cookie.parse(req.headers.cookie || ''); } catch { return {}; }
}
function setSession(res, payload){
  if(!process.env.APP_SECRET){
    throw new Error('missing APP_SECRET');
  }
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
  if(!token || !process.env.APP_SECRET) return null;
  try { return jwt.verify(token, process.env.APP_SECRET); } catch { return null; }
}
function routeOf(req){
  const u = new URL(req.url, 'http://x');
  const p = u.pathname.replace(/^\/+/, '');
  return p.startsWith('api/') ? p.slice(4) : p;
}

// Stripe helpers
function getStripe(){
  if (!process.env.STRIPE_SECRET_KEY) {
    const e = new Error('missing STRIPE_SECRET_KEY');
    e.statusCode = 500;
    throw e;
  }
  return new Stripe(process.env.STRIPE_SECRET_KEY);
}
async function ensureCustomerId(stripe, sess){
  if(sess?.customerId) return sess.customerId;
  if(!sess?.email) return null;
  const found = await stripe.customers.search({ query: `email:'${sess.email}'`, limit: 1 });
  if(found.data.length) return found.data[0].id;
  const created = await stripe.customers.create({ email: sess.email, name: sess.name || undefined, metadata:{ app:'taply' }});
  return created.id;
}
function normalizeSub(sub){
  if(!sub) return null;
  const price = sub.items?.data?.[0]?.price || null;
  return {
    id: sub.id,
    status: sub.status,
    current_period_end: sub.current_period_end,
    plan: { nickname: price?.nickname || null },
    price: { id: price?.id || null, nickname: price?.nickname || null }
  };
}
async function hasValidSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
  return subs.data.some(s => ['active','trialing','past_due'].includes(s.status));
}

/* ========= ENVÍOS (SendGrid y WhatsApp opcionales) ========= */
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
async function sendWhatsApp({toNumber, body}){
  try{
    if(!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_WHATSAPP_FROM || !toNumber) return;
    const { default: Twilio } = await import('twilio');
    const client = Twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    const from = 'whatsapp:' + process.env.TWILIO_WHATSAPP_FROM;
    const to   = 'whatsapp:' + (toNumber.startsWith('+') ? toNumber : `${process.env.WHATSAPP_DEFAULT_PREFIX || '+34'}${toNumber}`);
    await client.messages.create({ from, to, body });
  }catch(e){ console.error('sendWhatsApp error', e); }
}

/* ================== Handlers ================== */

// POST /api/register
async function register(req, res){
  const { email, password, name } = getBody(req);
  if(!email || !password || password.length<6) return res.status(400).json({ error:'Email y contraseña (mín. 6) requeridos' });
  const stripe = getStripe();

  const found = await stripe.customers.search({ query: `email:'${email}'`, limit: 1 });
  let customer = found.data[0];
  if(!customer){
    customer = await stripe.customers.create({ email, name, metadata:{ app:'taply' }});
  }
  const hash = await bcrypt.hash(password, 10);
  const meta = Object.assign({}, customer.metadata||{}, { taply_pass_hash: hash, app:'taply' });
  await stripe.customers.update(customer.id, { metadata: meta, name: name || customer.name || undefined });

  setSession(res, { email, name: customer.name || name || null, customerId: customer.id });
  return res.status(200).json({ user:{ email, name: customer.name || name || null, customerId: customer.id }});
}

// POST /api/login
async function login(req, res){
  const { email, password } = getBody(req);
  if(!email || !password) return res.status(400).json({ error:'Email y contraseña requeridos' });
  const stripe = getStripe();
  const found = await stripe.customers.search({ query: `email:'${email}'`, limit: 1 });
  if(!found.data.length) return res.status(401).json({ error:'Cuenta no encontrada' });
  const customer = found.data[0];
  const hash = customer.metadata?.taply_pass_hash;
  if(!hash) return res.status(401).json({ error:'Cuenta sin contraseña. Regístrate de nuevo.' });
  const ok = await bcrypt.compare(password, hash);
  if(!ok) return res.status(401).json({ error:'Credenciales inválidas' });
  setSession(res, { email, name: customer.name || null, customerId: customer.id });
  return res.status(200).json({ user:{ email, name: customer.name || null, customerId: customer.id }});
}

// POST /api/logout
async function logout(_req, res){
  clearSession(res);
  return res.status(200).json({ ok:true });
}

// GET /api/session
async function session(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(200).json({ user:null });
  const stripe = getStripe();
  const subs = await stripe.subscriptions.list({
    customer: sess.customerId, status: 'all', expand: ['data.items.data.price']
  });
  const order = { active:3, trialing:2, past_due:1 };
  const best = subs.data.sort((a,b)=> (order[b.status]||0)-(order[a.status]||0) || (b.current_period_end||0)-(a.current_period_end||0))[0];
  return res.status(200).json({
    user: {
      email: sess.email,
      name: sess.name || null,
      customerId: sess.customerId,
      subscription: normalizeSub(best),
      subscription_status: best?.status || null,
      current_period_end: best?.current_period_end || null
    }
  });
}

// POST /api/create-portal-session
async function createPortalSession(req, res){
  const sess = getSessionFromCookie(req);
  if(!sess?.customerId) return res.status(401).json({ error:'No autenticado' });
  const stripe = getStripe();
  const portal = await stripe.billingPortal.sessions.create({
    customer: sess.customerId,
    return_url: appBase(req) + '/suscripciones.html#cuenta'
  });
  return res.status(200).json({ url: portal.url });
}

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

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    ui_mode: 'hosted',
    line_items: [{ price, quantity: 1 }],
    success_url: `${appBase(req)}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appBase(req)}/cancelado.html`,
    phone_number_collection: { enabled: true },
    metadata: { type: 'subscription', tier, frequency },
    ...(customerId ? { customer: customerId } : {})
  });

  if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
  return res.status(200).json({ url: session.url });
}

// POST /api/buy-nfc  (pago único, requiere suscripción activa)
async function buyNfc(req, res){
  if (!process.env.PRICE_ID_NFC) return res.status(500).json({ error: 'missing_nfc_price_id' });

  const sess = getSessionFromCookie(req);
  if(!sess) return res.status(401).json({ error: 'auth_required' });

  const { quantity = 1 } = getBody(req);
  const qty = Math.max(1, Math.min(Number(quantity) || 1, 99));

  const stripe = getStripe();
  const customerId = await ensureCustomerId(stripe, sess);
  if(!customerId) return res.status(401).json({ error:'auth_required' });

  const ok = await hasValidSubscription(stripe, customerId);
  if(!ok) return res.status(403).json({ error: 'subscription_required' });

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    ui_mode: 'hosted',
    line_items: [{ price: process.env.PRICE_ID_NFC, quantity: qty }],
    success_url: `${appBase(req)}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appBase(req)}/cancelado.html`,
    allow_promotion_codes: true,
    phone_number_collection: { enabled: true },
    shipping_address_collection: { allowed_countries: ['ES'] },
    metadata: { type: 'nfc', qty: String(qty) },
    customer: customerId
  });

  if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
  return res.status(200).json({ url: session.url });
}

/* ========= POST /api/post-pago  (EMAIL/WHATSAPP tras compra) ========= */
async function postPago(req, res){
  const stripe = getStripe();
  const url = new URL(req.url, 'http://x');
  const qpSession = url.searchParams.get('session_id');
  const { session_id: bodySession, type } = getBody(req);
  const sessionId = bodySession || qpSession || null;

  let buyerEmail = null;
  let buyerPhone = null;
  let lineSummary = '';
  let amountText = '';

  if(sessionId){
    try{
      const cs = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items','customer_details'] });
      buyerEmail = cs.customer_details?.email || null;
      buyerPhone = cs.customer_details?.phone || null;
      const li = cs.line_items?.data || [];
      lineSummary = li.map(i => `${i.quantity} × ${i.description || i.price?.nickname || i.price?.id}`).join(', ');
      amountText = (cs.amount_total!=null && cs.currency) ? `${(cs.amount_total/100).toFixed(2)} ${cs.currency.toUpperCase()}` : '';
    }catch(e){
      console.error('post-pago retrieve error', e);
    }
  }

  // Fallback a email de sesión si no tenemos uno del checkout
  const sess = getSessionFromCookie(req);
  if(!buyerEmail && sess?.email) buyerEmail = sess.email;

  // ===== Email al comprador (si tenemos email)
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

  // ===== Email al administrador (EMAIL_FROM)
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

  // ===== WhatsApp (opcional)
  if(buyerPhone){
    await sendWhatsApp({ toNumber: buyerPhone, body: '¡Gracias! Hemos recibido tu compra. Te escribimos ahora con los pasos.' });
  }

  return res.status(200).json({ ok:true });
}

/* ================== Router ================== */
export default async function handler(req, res){
  try{
    const route = routeOf(req);

    if (req.method === 'GET' && route === 'session') return session(req,res);

    if (req.method === 'POST') {
      if (route === 'register') return register(req,res);
      if (route === 'login') return login(req,res);
      if (route === 'logout') return logout(req,res);
      if (route === 'create-portal-session') return createPortalSession(req,res);
      if (route === 'create-checkout-session') return createCheckoutSession(req,res);
      if (route === 'buy-nfc') return buyNfc(req,res);
      if (route === 'post-pago') return postPago(req,res);
    }

    return res.status(404).json({ error:'not_found', route, method:req.method });
  }catch(e){
    const code = e?.statusCode || 500;
    console.error('api error', e);
    return res.status(code).json({ error:'server_error', detail: e?.message || String(e) });
  }
}
