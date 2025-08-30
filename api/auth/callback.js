// /api/auth/callback.js
import { verify, sign, setCookie } from './_session.js';

export default async function handler(req, res){
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  const data = verify(token);
  if(!data?.email) return res.status(400).send('Enlace inválido o expirado');

  // crea sesión de 30 días
  const sess = sign({ email: data.email }, 30*24*60*60);
  setCookie(res, sess);

  // redirige a la sección "Tu cuenta"
  res.writeHead(302, { Location: '/suscripciones.html#cuenta' });
  res.end();
}
