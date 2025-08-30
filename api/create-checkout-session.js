// api/create-checkout-session.js
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { tier, frequency } = JSON.parse(req.body || '{}');

    const PRICE = {
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

    const price = PRICE[frequency]?.[tier];
    if (!price) return res.status(400).json({ error: 'price_not_found' });

    const origin =
      (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-host'])
        ? `${req.headers['x-forwarded-proto']}://${req.headers['x-forwarded-host']}`
        : `https://${process.env.VERCEL_URL}`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price, quantity: 1 }],
      success_url: `${origin}/exito.html`,
      cancel_url: `${origin}/cancelado.html`,
    });

    res.status(200).json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'stripe_error' });
  }
};
