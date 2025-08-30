// /api/_utils.js
import crypto from 'crypto';

export async function readJson(req){
  return await new Promise((resolve, reject)=>{
    let data=''; req.on('data',c=>data+=c);
    req.on('end',()=>{ try{ resolve(data?JSON.parse(data):{});}catch(e){reject(e);} });
    req.on('error',reject);
  });
}

/* Cookie de sesión firmada (sin dependencias externas) */
const COOKIE = 'taply_session';
const MAX_AGE = 60*60*24*365; // 1 año

function b64url(buf){ return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function hmac(data, secret){ return b64url(crypto.createHmac('sha256', secret).update(data).digest()); }

export function setSession(res, payload){
  const secret = process.env.AUTH_SECRET;
  const body = b64url(JSON.stringify(payload));
  const sig = hmac(body, secret);
  const value = `${body}.${sig}`;
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${COOKIE}=${value}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; SameSite=Lax; ${isProd?'Secure;':''}`);
}

export function clearSession(res){
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `taply_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; ${isProd?'Secure;':''}`);
}

export function getSession(req){
  const header = req.headers.cookie || '';
  const part = header.split(';').map(v=>v.trim()).find(v=>v.startsWith('taply_session='));
  if(!part) return null;
  const value = part.split('=')[1];
  const [body, sig] = value.split('.');
  const sig2 = hmac(body, process.env.AUTH_SECRET);
  if(sig !== sig2) return null;
  try{
    return JSON.parse(Buffer.from(body.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString());
  }catch{ return null; }
}
