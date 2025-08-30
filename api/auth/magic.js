// /api/auth/magic.js
import jwt from 'jsonwebtoken';
import { json, setCookie, userIdFromEmail } from '../_utils.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return json(res, 405, { ok:false });

  const { token, redirect = '/suscripciones.html#cuenta' } = Object.fromEntries(new URL(req.url, 'http://x').searchParams);
  try {
    const { email } = jwt.verify(token, process.env.SESSION_SECRET);
    const user = { id: userIdFromEmail(email), email };
    setCookie(res, 'taply_session', jwt.sign(user, process.env.SESSION_SECRET, { expiresIn: '180d' }));
    res.statusCode = 302;
    res.setHeader('Location', redirect);
    res.end();
  } catch (e) {
    res.statusCode = 302;
    res.setHeader('Location', '/account.html#expired');
    res.end();
  }
}