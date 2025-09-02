import Stripe from 'stripe';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

const COOKIE_NAME = 'taply_session';

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}
function getBody(req) {
  if (!req.body) return {};
  return (typeof req.body === 'string') ? JSON.parse(req.body) : req.body;
}

/* === Helpers sesión === */
function getCookies(req){
  try { return cookie.parse(req.headers.cookie || ''); } catch { return {}; }
}
function getSessionFromCookie(req){
  const token = getCookies(req)[COOKIE_NAME];
  if(!token) return null;
  if(!process.env.APP_SECRET) return null;
  try { return jwt.verify(token, process.env.APP_SECRET); } catch { return null; }
}
async function ensureCustomerId(stripe, sess){
  if(sess?.customerId) return sess.customerId;
  if(!sess?.email) return null;
  const found = await stripe.customers.search({ query: `email:'${sess.email}'`, limit: 1 });
  if(found.data.length) return found.data[0].id;
  const created = await stripe.customers.create({ email: sess.email, name: sess.name || undefined, metadata:{ app:'taply' }});
  return created.id;
}

// Comprobación de suscripción vigente (active | trialing | past_due)
async function hasValidSubscription(stripe, customerId){
  const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
  return subs.data.some(s => ['active','trialing','past_due'].includes(s.status));
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });

  try {
    if (!process.env.STRIPE_SECRET_KEY) return res.status(500).json({ error: 'missing_stripe_key' });
    if (!process.env.PRICE_ID_NFC)     return res.status(500).json({ error: 'missing_nfc_price_id' });

    // === ADDED: exigir sesión (login)
    const sess = getSessionFromCookie(req);
    if(!sess) return res.status(401).json({ error: 'auth_required' });

    const { quantity = 1 } = getBody(req);
    const qty = Math.max(1, Math.min(Number(quantity) || 1, 99));

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    // === ADDED: customerId y verificación de suscripción
    const customerId = await ensureCustomerId(stripe, sess);
    if(!customerId) return res.status(401).json({ error: 'auth_required' });

    const ok = await hasValidSubscription(stripe, customerId);
    if(!ok) return res.status(403).json({ error: 'subscription_required' });

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      ui_mode: 'hosted',
      line_items: [{ price: process.env.PRICE_ID_NFC, quantity: qty }],
      success_url: `${process.env.BASE_URL || baseUrl(req)}/exito.html`,
      cancel_url:  `${process.env.BASE_URL || baseUrl(req)}/cancelado.html`,
      allow_promotion_codes: true,

      // 👉 obligar dirección y teléfono
      phone_number_collection: { enabled: true },
      shipping_address_collection: {
        allowed_countries: ['ES'] // añade más si quieres ['ES','PT',...]
      },

      // opcional: metadata útil
      metadata: { type: 'nfc', qty: String(qty) },

      // === ADDED: vincular con el mismo Customer del usuario
      customer: customerId
    });

    if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error', e);
    return res.status(500).json({ error: 'stripe_error', detail: e?.message });
  }
}
