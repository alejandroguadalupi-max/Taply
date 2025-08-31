// TAPLY/api/email-test.js
import sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY || '');

export default async function handler(req, res) {
  try {
    const to = (req.query.to || '').trim(); // /api/email-test?to=correo@dominio.com&type=nfc&name=Carlos&qty=3
    const type = (req.query.type || 'nfc').trim(); // 'nfc' | 'sub'
    if (!to) return res.status(400).json({ error: 'missing_to' });

    const name = req.query.name || 'cliente';
    let subject, text, html;

    if (type === 'sub') {
      const plan = req.query.plan || 'Taply Plan';
      ({ subject, text, html } = buildSub({ name, plan }));
    } else {
      const qty = req.query.qty || '1';
      ({ subject, text, html } = buildNfc({ name, qty }));
    }

    await sgMail.send({
      to,
      from: process.env.EMAIL_FROM || 'Taply <no-reply@taply.local>',
      replyTo: process.env.EMAIL_REPLY_TO || '',
      subject, text, html
    });

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('email-test error', e?.response?.body || e?.message || e);
    res.status(500).json({ error: e?.message || 'send_error' });
  }
}

/* Templates mínimas para prueba */
function buildNfc({ name, qty }) {
  const subject = `Compra de ${qty} NFC recibida`;
  const text = `Hola ${name}, hemos recibido tu compra de ${qty} NFC.`;
  const html = `<p>Hola <strong>${escapeHtml(name)}</strong>, hemos recibido tu compra de <strong>${escapeHtml(qty)}</strong> NFC.</p>`;
  return { subject, text, html };
}
function buildSub({ name, plan }) {
  const subject = `Suscripción (${plan}) activa`;
  const text = `Hola ${name}, tu suscripción (${plan}) está activa.`;
  const html = `<p>Hola <strong>${escapeHtml(name)}</strong>, tu suscripción <strong>${escapeHtml(plan)}</strong> está activa.</p>`;
  return { subject, text, html };
}
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
