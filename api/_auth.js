// /api/_auth.js
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const COOKIE_NAME = 'taply_session';

function parseCookies(req){
  try { return cookie.parse(req.headers.cookie || ''); } catch { return {}; }
}

function setSession(res, payload){
  const token = jwt.sign(payload, process.env.APP_SECRET, { expiresIn: '90d' });
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 90
  }));
}

function clearSession(res){
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, '', {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', path: '/', maxAge: 0
  }));
}

function getSession(req){
  const c = parseCookies(req);
  const token = c[COOKIE_NAME];
  if(!token) return null;
  try { return jwt.verify(token, process.env.APP_SECRET); }
  catch { return null; }
}

module.exports = { setSession, clearSession, getSession };
