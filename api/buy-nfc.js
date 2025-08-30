import Stripe from 'stripe';

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
    if (!process.env.PRICE_ID_NFC)     return res.status(500).json({ error: 'missing_nfc_price_id' });

    const { quantity = 1 } = getBody(req);
    const qty = Math.max(1, Math.min(Number(quantity) || 1, 99));

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
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

      // opcional: te dejo metadata útil
      metadata: { type: 'nfc', qty: String(qty) }
    });

    if (!session?.url) return res.status(500).json({ error: 'no_session_url' });
    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error', e);
    return res.status(500).json({ error: 'stripe_error', detail: e?.message });
  }
}
