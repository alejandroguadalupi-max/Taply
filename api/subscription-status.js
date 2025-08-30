// /api/subscription-status.js
import { requireUser, json, stripe, getOrCreateCustomerId } from './_utils.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return json(res, 405, { ok:false });
  const user = requireUser(req, res); if (!user) return;

  try {
    const customer = await getOrCreateCustomerId(user);
    const subs = await stripe.subscriptions.list({ customer, status: 'all', expand: ['data.items.price'] });
    const current = subs.data.find(s => ['active','trialing','past_due','incomplete','incomplete_expired','unpaid'].includes(s.status));
    if (!current) return json(res, 200, { ok:true, active:false, subscriptions: [] });

    const item = current.items.data[0];
    return json(res, 200, {
      ok: true,
      active: ['active','trialing','past_due'].includes(current.status),
      status: current.status,
      cancel_at_period_end: current.cancel_at_period_end,
      current_period_end: current.current_period_end,
      price_id: item?.price?.id || null,
      plan_nickname: item?.price?.nickname || item?.price?.id || null
    });
  } catch (e) {
    console.error('Status error:', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
