// /api/session.js
const { stripe } = require('./_stripe');
const { getSession } = require('./_auth');

function normalizeSub(sub){
  if(!sub) return null;
  const price = sub.items?.data?.[0]?.price || null;
  return {
    id: sub.id,
    status: sub.status,
    current_period_end: sub.current_period_end,
    plan: { nickname: price?.nickname || null },
    price: { id: price?.id || null, nickname: price?.nickname || null }
  };
}

module.exports = async (req, res) => {
  try{
    const sess = getSession(req);
    if(!sess) return res.status(200).json({ user:null });

    // Busca la suscripción "vigente" del customer
    const subs = await stripe.subscriptions.list({
      customer: sess.customerId,
      status: 'all',
      expand: ['data.items.data.price']
    });

    // Escoge la más relevante: active > trialing > past_due > (si no hay, null)
    const order = { active: 3, trialing: 2, past_due: 1, canceled: 0, unpaid: 0, incomplete: 0, incomplete_expired: 0, paused: 0 };
    const best = subs.data.sort((a,b)=> (order[b.status]||0) - (order[a.status]||0) || (b.current_period_end||0)-(a.current_period_end||0))[0];

    return res.status(200).json({
      user: {
        email: sess.email,
        name: sess.name || null,
        customerId: sess.customerId,
        subscription: normalizeSub(best),
        subscription_status: best?.status || null,
        current_period_end: best?.current_period_end || null
      }
    });
  }catch(err){
    console.error('session error', err);
    return res.status(500).json({ error:'Error obteniendo sesión' });
  }
};
