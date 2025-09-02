import Stripe from 'stripe';
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
// Si no viene customerId pero sí email, buscamos/creamos el Customer en Stripe.
async function ensureCustomerId(stripe, sess){
  if(sess?.customerId) return sess.customerId;
  if(!sess?.email) return null;
  const found = await stripe.customers.search({ query: `email:'${sess.email}'`, limit: 1 });
  if(found.data.length) return found.data[0].id;
  const created = await stripe.customers.create({ email: sess.email, name: sess.name || undefined, metadata:{ app:'taply' }});
  return created.id;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });

  try {
    if (!process.env.STRIPE_SECRET_KEY) return res.status(500).json({ error: 'missing_stripe_key' });

    const { tier, frequency } = getBody(req);
    if (!tier || !frequency) return res.status(400).json({ error: 'missing_params' });

    const price = PRICES?.[frequency]?.[tier];
    if (!price) return res.status(400).json({ error: 'price_not_found' });

    // === ADDED: exigir sesión (login)
    const sess = getSessionFromCookie(req);
    if(!sess) return res.status(401).json({ error: 'auth_required' });

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    // === ADDED: adjuntar el customer a la sesión de checkout
    const customerId = await ensureCustomerId(stripe, sess);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      ui_mode: 'hosted',
      line_items: [{ price, quantity: 1 }],
      success_url: `${process.env.BASE_URL || baseUrl(req)}/exito.html`,
      cancel_url:  `${process.env.BASE_URL || baseUrl(req)}/cancelado.html`,

      // 👉 pedir teléfono también en suscripción
      phone_number_collection: { enabled: true },

      // opcional: metadata para distinguir
      metadata: { type: 'subscription', tier, frequency },

      // === ADDED: vincular con el mismo Customer del usuario
      ...(customerId ? { customer: customerId } : {}),
      // (Si quieres prellenar, también se podría: customer_email: sess.email)
    });

    if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('create-checkout-session error:', e);
    return res.status(500).json({ error: 'stripe_error', detail: e?.message });
  }
}
