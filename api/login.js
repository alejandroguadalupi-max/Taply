// /api/login.js
const { stripe } = require('./_stripe');
const { setSession } = require('./_auth');
const bcrypt = require('bcryptjs');

module.exports = async (req, res) => {
  try{
    if(req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({ error:'Email y contraseña requeridos' });

    const found = await stripe.customers.search({ query: `email:'${email}'`, limit: 1 });
    if(!found.data.length) return res.status(401).json({ error:'Cuenta no encontrada' });
    const customer = found.data[0];
    const hash = customer.metadata?.taply_pass_hash;
    if(!hash) return res.status(401).json({ error:'Cuenta sin contraseña. Regístrate de nuevo.' });

    const ok = await bcrypt.compare(password, hash);
    if(!ok) return res.status(401).json({ error:'Credenciales inválidas' });

    setSession(res, { email, name: customer.name || null, customerId: customer.id });
    return res.status(200).json({ user: { email, name: customer.name || null, customerId: customer.id } });
  }catch(err){
    console.error('login error', err);
    return res.status(500).json({ error: 'Error al iniciar sesión' });
  }
};
