// /api/logout.js
const { clearSession } = require('./_auth');

module.exports = async (req, res) => {
  try{
    if(req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
    clearSession(res);
    return res.status(200).json({ ok:true });
  }catch(err){
    return res.status(500).json({ error:'Error al cerrar sesión' });
  }
};
