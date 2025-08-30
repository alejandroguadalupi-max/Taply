// /api/subscription-status.js
import Stripe from 'stripe';
import { getSessionUser, json } from './_utils.js';

export default async function handler(req, res){
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });

  const user = getSessionUser(req);
  if (!user?.email) return json(res, 401, { ok:false, error:'UNAUTHORIZED' });

  try{
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    let customerId = user.customerId;

    if(!customerId){
      const existing = await stripe.customers.list({ email: user.email, limit: 1 });
      customerId = existing?.data?.[0]?.id || null;
    }
    if(!customerId) return json(res, 200, { active:false });

    const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
    const sub = subs.data.find(s => ['active','trialing','past_due','unpaid'].includes(s.status));

    if(!sub) return json(res, 200, { active:false, customerId });

    const price = sub.items.data[0]?.price;
    const tier = price?.nickname || price?.product || 'Plan';
    const interval = price?.recurring?.interval || '';
    return json(res, 200, {
      ok:true,
      active: ['active','trialing','past_due','unpaid'].includes(sub.status),
      status: sub.status,
      tier,
      interval,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: sub.cancel_at_period_end || false,
      customerId
    });
  }catch(e){
    console.error('subscription-status', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
