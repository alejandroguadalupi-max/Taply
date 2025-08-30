// /api/create-portal-session.js
import Stripe from 'stripe';
import { getSession } from './_utils';

export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  try{
    const sess = getSession(req);
    if(!sess?.customerId) return res.status(401).json({error:'Debes iniciar sesión'});

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const portal = await stripe.billingPortal.sessions.create({
      customer: sess.customerId,
      return_url: `${process.env.BASE_URL}/suscripciones.html`
    });
    return res.status(200).json({url: portal.url});
  }catch(e){
    console.error('portal error', e);
    return res.status(500).json({error:'No se pudo abrir el portal ahora mismo'});
  }
}
