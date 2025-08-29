// /api/buy-nfc.js
import Stripe from 'stripe';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const { quantity } = req.body || {};
    const q = Number(quantity);

    if (!Number.isInteger(q) || q < 1 || q > 500) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: process.env.PRICE_ID_NFC, quantity: q }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      phone_number_collection: { enabled: true },
      billing_address_collection: 'auto',
      // shipping_address_collection: { allowed_countries: ['ES'] }, // activa si envías físico
    });

    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo crear el checkout' });
  }
}
