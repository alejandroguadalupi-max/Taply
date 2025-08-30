import Stripe from 'stripe';

const PRICES = {
  monthly: {
    basic: process.env.PRICE_BASIC_MONTHLY,
    medio: process.env.PRICE_MEDIO_MONTHLY,
    pro:   process.env.PRICE_PRO_MONTHLY,
  },
  annual: {
    basic: process.env.PRICE_BASIC_ANNUAL,
    medio: process.env.PRICE_MEDIO_ANNUAL,
    pro:   process.env.PRICE_PRO_ANNUAL,
  },
};

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  try {
    // ❌ nada de JSON.parse
    const { tier, frequency } = req.body || {};
    const price = PRICES?.[frequency]?.[tier];
    if (!price) {
      console.error('price_not_found', { tier, frequency });
      res.status(400).json({ error: 'price_not_found' });
      return;
    }

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price, quantity: 1 }],
      success_url: `${process.env.BASE_URL || baseUrl(req)}/exito.html`,
      cancel_url:  `${process.env.BASE_URL || baseUrl(req)}/cancelado.html`,
      // opcional: ui_mode 'hosted' para garantizar session.url
      // ui_mode: 'hosted'
    });

    res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('create-checkout-session error', e);
    res.status(500).json({ error: 'stripe_error' });
  }
}
