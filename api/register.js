// /api/register.js (Vercel/Node)
const { stripe } = require('./_stripe');
const { setSession } = require('./_auth');
const bcrypt = require('bcryptjs');

module.exports = async (req, res) => {
  try{
    if(req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
    const { email, password, name } = req.body || {};
    if(!email || !password || password.length < 6){
      return res.status(400).json({ error: 'Email y contraseña (mín. 6) requeridos' });
    }

    // Busca o crea Customer en Stripe
    let customer = null;
    const found = await stripe.customers.search({ query: `email:'${email}'`, limit: 1 });
    if(found.data.length) customer = found.data[0];
    else customer = await stripe.customers.create({ email, name, metadata: { app: 'taply' } });

    // Guarda hash de contraseña en metadata (hash, no texto plano)
    const hash = await bcrypt.hash(password, 10);
    const meta = Object.assign({}, customer.metadata || {}, { taply_pass_hash: hash, app: 'taply' });
    if(!customer.metadata || !customer.metadata.taply_pass_hash){
      customer = await stripe.customers.update(customer.id, { metadata: meta, name: name || customer.name || undefined });
    }

    // Crea sesión
    setSession(res, { email, name: customer.name || name || null, customerId: customer.id });
    // Devuelve user + (si hay) estado de suscripción
    return res.status(200).json({ user: { email, name: customer.name || name || null, customerId: customer.id } });
  }catch(err){
    console.error('register error', err);
    return res.status(500).json({ error: 'Error al registrar' });
  }
};
