// /api/create-checkout-session.js
import { requireUser, readJson, json, stripe, getOrCreateCustomerId } from './_utils.js';

const MONTH = { basic:'PRICE_ID_BASIC_MONTH', medio:'PRICE_ID_MEDIO_MONTH', pro:'PRICE_ID_PRO_MONTH' };
const YEAR  = { basic:'PRICE_ID_BASIC_YEAR',  medio:'PRICE_ID_MEDIO_YEAR',  pro:'PRICE_ID_PRO_YEAR'  };

export default async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { ok:false });

  const user = requireUser(req, res); if (!user) return;
  const { tier, frequency } = await readJson(req).catch(() => ({}));
  const key = (frequency === 'annual' ? YEAR : MONTH)[tier];
  const priceId = key && process.env[key];
  if (!priceId) return json(res, 400, { ok:false, error:'BAD_PRICE' });

  try {
    const customer = await getOrCreateCustomerId(user);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      allow_promotion_codes: true,
      metadata: { userId: user.id, plan: tier, frequency }
    });
    return json(res, 200, { ok:true, url: session.url });
  } catch (e) {
    console.error('Create checkout error:', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}

