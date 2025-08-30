// /api/auth/[...all].js
import callbackHandler from './callback.js';
import loginHandler from './login.js';
import logoutHandler from './logout.js';
import magicHandler from './magic.js';
import meHandler from './me.js';
import sendMagicHandler from './send-magic-link.js';
import signupHandler from './signup.js';
import startHandler from './start.js';

import { json, setCookie } from '../_utils.js';
import jwt from 'jsonwebtoken';

// === GOOGLE OAUTH (nuevo) ===
async function googleStart(req, res) {
  const { searchParams } = new URL(req.url, 'http://x');
  const redirect = searchParams.get('redirect') || '/account.html';
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI, // BASE_URL + /api/auth/oauth/google/callback
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    include_granted_scopes: 'true',
    state: Buffer.from(JSON.stringify({ redirect })).toString('base64url'),
    prompt: 'consent'
  });
  res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}` });
  res.end();
}

async function googleCallback(req, res) {
  const url = new URL(req.url, 'http://x');
  const code = url.searchParams.get('code');
  const stateRaw = url.searchParams.get('state') || '';
  const { redirect = '/account.html' } = JSON.parse(Buffer.from(stateRaw, 'base64url').toString() || '{}');

  if (!code) return json(res, 400, { ok:false, error:'NO_CODE' });

  // Intercambiar code por tokens
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.GOOGLE_REDIRECT_URI
    })
  });
  if (!tokenRes.ok) return json(res, 400, { ok:false, error:'TOKEN_EXCHANGE_FAILED' });

  const tokens = await tokenRes.json();
  // Sacar email del id_token
  const [, payload] = String(tokens.id_token || '').split('.');
  const info = payload ? JSON.parse(Buffer.from(payload, 'base64').toString()) : {};
  const email = info.email;
  const name = info.name || email?.split('@')[0] || 'Usuario';

  if (!email) return json(res, 400, { ok:false, error:'NO_EMAIL' });

  // Crea sesión (JWT en cookie)
  const user = { id: `u_${email.toLowerCase()}`, email, name };
  const token = jwt.sign(user, process.env.SESSION_SECRET, { expiresIn: '180d' });
  setCookie(res, 'taply_session', token);

  res.writeHead(302, { Location: redirect });
  res.end();
}

// === APPLE (esqueleto listo; puedes completarlo después) ===
async function appleStart(_req, res) {
  // TODO: genera client_secret JWT y redirige a Apple
  return json(res, 501, { ok:false, error:'APPLE_TODO' });
}
async function appleCallback(_req, res) {
  return json(res, 501, { ok:false, error:'APPLE_TODO' });
}

// ---------- Router ----------
const table = {
  '/callback': callbackHandler,
  '/login': loginHandler,
  '/logout': logoutHandler,
  '/magic': magicHandler,
  '/me': meHandler,
  '/send-magic-link': sendMagicHandler,
  '/signup': signupHandler,
  '/start': startHandler,

  // OAuth
  '/oauth/google/start': googleStart,
  '/oauth/google/callback': googleCallback,
  '/oauth/apple/start': appleStart,
  '/oauth/apple/callback': appleCallback,
};

export default async function handler(req, res) {
  // ruta relativa dentro de /api/auth
  const path = new URL(req.url, 'http://x').pathname.replace(/^\/api\/auth/, '') || '/me';
  const fn = table[path];
  if (!fn) return json(res, 404, { ok:false, error:'NOT_FOUND', path });
  try {
    return await fn(req, res);
  } catch (e) {
    console.error('AUTH router error', path, e);
    return json(res, 500, { ok:false, error:'SERVER_ERROR' });
  }
}
