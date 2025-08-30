import Stripe from 'stripe';

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

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });

  try {
    if (!process.env.STRIPE_SECRET_KEY) return res.status(500).json({ error: 'missing_stripe_key' });

    const { tier, frequency } = getBody(req);
    if (!tier || !frequency) return res.status(400).json({ error: 'missing_params' });

    const price = PRICES?.[frequency]?.[tier];
    if (!price) return res.status(400).json({ error: 'price_not_found' });

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      ui_mode: 'hosted',
      line_items: [{ price, quantity: 1 }],
      success_url: `${process.env.BASE_URL || baseUrl(req)}/exito.html`,
      cancel_url:  `${process.env.BASE_URL || baseUrl(req)}/cancelado.html`,

      // 👉 pedir teléfono también en suscripción
      phone_number_collection: { enabled: true },

      // opcional: metadata para distinguir
      metadata: { type: 'subscription', tier, frequency }
    });

    if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('create-checkout-session error:', e);
    return res.status(500).json({ error: 'stripe_error', detail: e?.message });
  }
}
