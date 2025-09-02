// /api/create-portal-session.js
const { stripe } = require('./_stripe');
const { getSession } = require('./_auth');

module.exports = async (req, res) => {
  try{
    if(req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
    const sess = getSession(req);
    if(!sess?.customerId) return res.status(401).json({ error:'No autenticado' });

    const portal = await stripe.billingPortal.sessions.create({
      customer: sess.customerId,
      return_url: (process.env.APP_BASE_URL || 'http://localhost:3000') + '/suscripciones.html#cuenta'
    });
    return res.status(200).json({ url: portal.url });
  }catch(err){
    console.error('portal error', err);
    return res.status(500).json({ error:'No se pudo crear el portal' });
  }
};
