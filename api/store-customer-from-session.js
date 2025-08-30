// /api/store-customer-from-session.js
import Stripe from 'stripe';
import { readJson, setSession, getSession } from './_utils';

export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  try{
    const { session_id } = await readJson(req);
    if(!session_id) return res.status(400).json({error:'Falta session_id'});

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const cs = await stripe.checkout.sessions.retrieve(session_id);
    const customerId = cs.customer;
    if(!customerId) return res.status(400).json({error:'La sesión no contiene customer'});

    // Si ya hay sesión, conserva email/name si existen; si no, intenta leer de Stripe
    let { email, name } = getSession(req) || {};
    if(!email || !name){
      const cust = await stripe.customers.retrieve(customerId);
      email = cust.email || email || '';
      name  = cust.name  || name  || '';
    }

    setSession(res, { customerId, email, name });
    return res.status(200).json({ok:true});
  }catch(e){
    console.error('store-customer-from-session error', e);
    return res.status(500).json({error:'No se pudo guardar el customer'});
  }
}
