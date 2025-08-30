// /api/my-subscriptions.js
import Stripe from 'stripe';
import { sessionEmail } from './auth/_session.js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export default async function handler(req, res){
  const email = sessionEmail(req);
  if(!email) return res.status(401).json({error:'auth'});

  try{
    // busca el customer por email (modo test/live basado en tu key)
    const found = await stripe.customers.search({ query: `email:'${email}'` });
    if((found?.data?.length||0) === 0){
      return res.json({ email, subscriptions: [] });
    }

    // si hay varios, coge el más reciente
    const customer = [...found.data].sort((a,b)=>b.created-a.created)[0];

    const subs = await stripe.subscriptions.list({
      customer: customer.id,
      status: 'all',
      expand: ['data.items.data.price.product']
    });

    const simplified = subs.data.map(s => ({
      id: s.id,
      status: s.status,
      cancel_at_period_end: !!s.cancel_at_period_end,
      current_period_end: s.current_period_end,
      plan: {
        price_id: s.items.data[0]?.price?.id,
        nickname: s.items.data[0]?.price?.nickname || s.items.data[0]?.price?.product?.name,
        unit_amount: s.items.data[0]?.price?.unit_amount,
        currency: s.items.data[0]?.price?.currency,
        interval: s.items.data[0]?.price?.recurring?.interval
      }
    }));

    res.json({ email, customerId: customer.id, subscriptions: simplified });
  }catch(e){
    console.error('my-subscriptions', e);
    res.status(500).json({error:'stripe'});
  }
}
