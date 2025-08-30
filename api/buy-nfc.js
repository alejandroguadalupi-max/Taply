import Stripe from 'stripe';

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
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    // ❌ nada de JSON.parse
    const { quantity = 1 } = req.body || {};
    const qty = Math.max(1, Math.min(Number(quantity) || 1, 99));

    const priceId = process.env.NFC_PRICE_ID;
    if (!priceId) {
      console.error('NFC_PRICE_ID missing');
      return res.status(400).json({ error: 'price_not_configured' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: priceId, quantity: qty }],
      success_url: `${process.env.BASE_URL || baseUrl(req)}/exito.html`,
      cancel_url:  `${process.env.BASE_URL || baseUrl(req)}/cancelado.html`,
      allow_promotion_codes: true,
      // ui_mode: 'hosted' // opcional
    });

    res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error', e);
    res.status(500).json({ error: 'stripe_error' });
  }
}
