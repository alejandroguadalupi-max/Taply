// /api/auth/send-magic-link.js
import jwt from 'jsonwebtoken';
import { readJson, json, sendEmail } from '../_utils.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { ok:false });

  const { email, redirect = '/suscripciones.html#cuenta' } = await readJson(req).catch(() => ({}));
  if (!email) return json(res, 400, { ok:false, error:'EMAIL_REQUIRED' });

  const token = jwt.sign({ email }, process.env.SESSION_SECRET, { expiresIn: '15m' });
  const url = `${process.env.BASE_URL}/api/auth/magic?token=${encodeURIComponent(token)}&redirect=${encodeURIComponent(redirect)}`;

  const html = `
    <div style="font-family:Inter,Arial,sans-serif">
      <h2>Accede a tu cuenta Taply</h2>
      <p>Haz clic para iniciar sesión de forma segura:</p>
      <p><a href="${url}" style="display:inline-block;padding:10px 16px;background:#7c3aed;color:#fff;border-radius:8px;text-decoration:none">Entrar</a></p>
      <p style="color:#555">El enlace expira en 15 minutos.</p>
    </div>
  `;
  await sendEmail({ to: email, subject: 'Tu acceso a Taply', html });
  return json(res, 200, { ok:true });
}
