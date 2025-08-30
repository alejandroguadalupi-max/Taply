// /api/auth/signup.js
import Stripe from 'stripe';
import { readJson, setSession } from '../_utils';
import crypto from 'crypto';

export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  try{
    const { name, email, password } = await readJson(req);
    if(!name || !email || !password) return res.status(400).json({error:'Faltan datos'});
    if(password.length < 8) return res.status(400).json({error:'La contraseña debe tener 8+ caracteres'});

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    // Buscar o crear Customer en Stripe
    const existing = await stripe.customers.list({ email, limit: 1 });
    let customer = existing.data[0];
    if(!customer){
      customer = await stripe.customers.create({ name, email, metadata: {} });
    }

    // Guardar hash en metadata
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');

    await stripe.customers.update(customer.id, {
      name,
      email,
      metadata: {
        app_pw_salt: salt,
        app_pw_hash: hash,
        app_source: 'site'
      }
    });

    setSession(res, { customerId: customer.id, email, name });
    return res.status(200).json({ ok:true });
  }catch(e){
    console.error('signup error', e);
    return res.status(500).json({error:'No se pudo crear la cuenta'});
  }
}
