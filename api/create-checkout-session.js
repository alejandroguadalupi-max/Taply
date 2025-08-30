import Stripe from 'stripe';

const PRICES = {
  monthly: {
    basic: process.env.PRICE_ID_BASIC_MONTH,
    medio: process.env.PRICE_ID_MEDIO_MONTH,
    pro:   process.env.PRICE_ID_PRO_MONTH
  },
  annual: {
    basic: process.env.PRICE_ID_BASIC_YEAR,
    medio: process.env.PRICE_ID_MEDIO_YEAR,
    pro:   process.env.PRICE_ID_PRO_YEAR
  }
};

async function readJson(req){
  return await new Promise((resolve, reject)=>{
    let data=''; req.on('data', c=>data+=c);
    req.on('end', ()=>{ try{ resolve(data?JSON.parse(data):{});} catch(e){ reject(e);} });
    req.on('error', reject);
  });
}

export default async function handler(req,res){
  if (req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
  try{
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const body = await readJson(req);
    const tier = body?.tier;
    const freq = body?.frequency === 'annual' ? 'annual' : 'monthly';
    if (!['basic','medio','pro'].includes(tier)) {
      return res.status(400).json({ error:'Plan inválido' });
    }
    const priceId = PRICES[freq][tier];
    if (!priceId) return res.status(500).json({ error:'Price no configurado' });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      phone_number_collection: { enabled: true },
      billing_address_collection: 'auto'
    });
    return res.status(200).json({ url: session.url });
  }catch(e){
    console.error('create-checkout-session error:', e);
    return res.status(500).json({ error: e?.message || 'No se pudo crear la suscripción' });
  }
}
