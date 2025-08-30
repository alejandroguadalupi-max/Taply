// /api/create-portal-session.js
import { requireUser, json, stripe, getOrCreateCustomerId } from './_utils.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { ok:false });

  const user = requireUser(req, res); if (!user) return;
  try {
    const customer = await getOrCreateCustomerId(user);
    const portal = await stripe.billingPortal.sessions.create({
      customer,
      return_url: `${process.env.BASE_URL}/suscripciones.html#cuenta`
    });
    return json(res, 200, { ok:true, url: portal.url });
  } catch (e) {
    console.error('Portal error:', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
