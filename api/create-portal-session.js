// /api/create-portal-session.js
import Stripe from 'stripe';
import { getSessionUser, json } from './_utils.js';

export default async function handler(req,res){
  if(req.method !== 'POST') return json(res, 405, { error:'Method not allowed' });

  const user = getSessionUser(req);
  if(!user?.email) return json(res, 401, { error:'UNAUTHORIZED' });

  try{
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    let customerId = user.customerId;

    if(!customerId){
      const existing = await stripe.customers.list({ email: user.email, limit: 1 });
      customerId = existing?.data?.[0]?.id || null;
      if(!customerId){
        // crea customer si no existe aún
        const c = await stripe.customers.create({ email: user.email, name: user.name || undefined });
        customerId = c.id;
      }
    }

    const base = process.env.BASE_URL || 'http://localhost:3000';
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${base}/index.html#mi-suscripcion`
    });

    return json(res, 200, { ok:true, url: session.url });
  }catch(e){
    console.error('create-portal-session', e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
