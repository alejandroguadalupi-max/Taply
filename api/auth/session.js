// /api/auth/_session.js
import crypto from 'crypto';

const COOKIE = 'taply_session';
const SEC = process.env.APP_SECRET || 'dev-secret-change-me';

function b64(s){ return Buffer.from(s).toString('base64url'); }
function ub64(s){ return Buffer.from(s, 'base64url').toString(); }

export function sign(payload, ttlSeconds){
  const data = { ...payload, exp: Math.floor(Date.now()/1000) + ttlSeconds };
  const body = b64(JSON.stringify(data));
  const sig = crypto.createHmac('sha256', SEC).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function verify(token){
  if(!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expSig = crypto.createHmac('sha256', SEC).update(body).digest('base64url');
  if(sig !== expSig) return null;
  const data = JSON.parse(ub64(body));
  if(!data.exp || Date.now()/1000 > data.exp) return null;
  return data;
}

export function readCookie(req, name=COOKIE){
  const raw = req.headers.cookie || '';
  const m = raw.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='));
  return m ? decodeURIComponent(m.split('=').slice(1).join('=')) : null;
}
export function setCookie(res, token, name=COOKIE, days=30){
  const maxAge = days*24*60*60;
  const cookie = `${name}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Secure`;
  res.setHeader('Set-Cookie', cookie);
}
export function clearCookie(res, name=COOKIE){
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`);
}

export function sessionEmail(req){
  const tok = readCookie(req);
  const data = verify(tok);
  return data?.email || null;
}
