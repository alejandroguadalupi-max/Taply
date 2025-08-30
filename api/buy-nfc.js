// /api/buy-nfc.js
import { requireUser, readJson, json, stripe } from './_utils.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { ok:false });
  const user = requireUser(req, res); if (!user) return;

  const { quantity = 1 } = await readJson(req).catch(() => ({}));

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: process.env.PRICE_ID_NFC, quantity: Math.max(1, Math.min(Number(quantity)||1, 99)) }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      metadata: { userId: user.id, type:'NFC' }
    });
    return json(res, 200, { ok:true, url: session.url });
  } catch (e) {
    console.error('Buy NFC error:', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
