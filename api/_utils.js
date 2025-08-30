// /api/_utils.js
import Stripe from 'stripe';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// ---- STRIPE ----
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16'
});

// ---- helpers HTTP/JSON ----
export async function readJson(req) {
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

export function json(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

// ---- Cookies / sesión ----
export function parseCookies(req) {
  const h = req.headers.cookie || '';
  return Object.fromEntries(
    h.split(';')
     .map(v => v.trim())
     .filter(Boolean)
     .map(v => {
       const i = v.indexOf('=');
       const k = decodeURIComponent(v.slice(0,i));
       const val = decodeURIComponent(v.slice(i+1));
       return [k, val];
     })
  );
}

export function setCookie(res, name, value, { maxAge = 60*60*24*180, path = '/', httpOnly = true, secure = true, sameSite = 'Lax' } = {}) {
  const parts = [
    `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `Max-Age=${maxAge}`,
    httpOnly ? 'HttpOnly' : '',
    secure ? 'Secure' : '',
    `SameSite=${sameSite}`
  ].filter(Boolean);
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${encodeURIComponent(name)}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

export function getSessionUser(req) {
  const cookies = parseCookies(req);
  const token = cookies['taply_session'];
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.SESSION_SECRET);
  } catch {
    return null;
  }
}

export function requireUser(req, res) {
  const user = getSessionUser(req);
  if (!user) {
    return json(res, 401, { ok:false, error:'AUTH_REQUIRED' });
  }
  return user;
}

// ---- email (Resend) ----
export async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.FROM_EMAIL || 'Taply <no-reply@taply.app>';
  if (!apiKey || !to) return;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from, to, subject, html })
  });
  if (!r.ok) {
    const t = await r.text();
    console.error('Resend error:', r.status, t);
  }
}

// ---- userId determinístico (email) ----
export function userIdFromEmail(email) {
  return 'u_' + crypto.createHash('sha256').update(String(email).toLowerCase()).digest('hex').slice(0,24);
}

// ---- Stripe Customer asociado al user ----
export async function getOrCreateCustomerId(user) {
  const q = `email:'${user.email}' AND metadata['userId']:'${user.id}'`;
  const found = await stripe.customers.search({ query: q });
  if (found.data[0]) return found.data[0].id;

  const cust = await stripe.customers.create({
    email: user.email,
    name: user.name || '',
    metadata: { userId: user.id }
  });
  return cust.id;
}
