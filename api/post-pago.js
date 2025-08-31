// TAPLY/api/post-pago.js
export const config = { api: { bodyParser: false } }; // NECESARIO para firmar con Stripe

import Stripe from 'stripe';
import getRawBody from 'raw-body';
import sgMail from '@sendgrid/mail';

// Config email
sgMail.setApiKey(process.env.SENDGRID_API_KEY || '');
const FROM_EMAIL = process.env.EMAIL_FROM || 'Taply <no-reply@taply.local>';
const REPLY_TO   = process.env.EMAIL_REPLY_TO || '';
const BCC_EMAIL  = process.env.EMAIL_BCC || '';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || '';
  if (!STRIPE_KEY) return res.status(500).json({ error: 'missing_stripe_key' });

  const stripe = new Stripe(STRIPE_KEY);

  // 1) Verificar firma de Stripe con cuerpo RAW
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    const raw = await getRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('[post-pago] event:', event.type, 'livemode:', event.livemode);
  } catch (err) {
    console.error('[post-pago] signature error:', err?.message || err);
    return res.status(400).json({ error: 'signature_error', detail: err?.message });
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // 2) Intentar expandir line_items (si falla, seguimos)
      let full = { line_items: { data: [] } };
      try {
        full = await stripe.checkout.sessions.retrieve(session.id, {
          expand: ['line_items.data.price.product']
        });
      } catch (e) {
        console.warn('[post-pago] retrieve failed:', e?.message || e);
      }

      // 3) Datos cliente
      const d = session.customer_details || {};
      let email = d.email || null;
      const name = d.name || 'cliente';

      if (!email && session.customer) {
        try {
          const customer = await stripe.customers.retrieve(session.customer);
          email = customer?.email || null;
        } catch {}
      }

      if (!email) {
        console.warn('[post-pago] no email found; skipping mail');
      } else {
        // 4) Seleccionar plantilla de email según modo
        if (session.mode === 'payment' || session.metadata?.type === 'nfc') {
          const items = full?.line_items?.data || [];
          const qty = items.reduce((acc, it) => acc + (it.quantity || 0), 0) || session.metadata?.qty || 1;
          const mail = buildNfcMail({ name, qty });
          await sendMail({ to: email, ...mail });
        } else if (session.mode === 'subscription' || session.metadata?.type === 'subscription') {
          const it = full?.line_items?.data?.[0];
          const planName =
            it?.price?.product?.name ||
            it?.description ||
            `${session.metadata?.tier || ''} ${session.metadata?.frequency || ''}`.trim() ||
            'tu suscripción';
          const mail = buildSubMail({ name, plan: planName });
          await sendMail({ to: email, ...mail });
        }
      }
    }

    // Nunca 500 a Stripe
    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('[post-pago] handler error:', e?.message || e);
    return res.status(200).json({ received: true, note: 'handled_with_errors' });
  }
}

/* ===== Helpers (emails) ===== */

function buildNfcMail({ name, qty }) {
  const first = firstName(name);
  const subject = `¡Gracias, ${first}! Compra de ${qty} NFC recibida ✅`;
  const text = [
    `Hola ${first},`,
    `Hemos recibido tu compra de ${qty} dispositivos NFC.`,
    `En breve te enviaremos la guía rápida y coordinamos el envío.`,
    `Si necesitas algo, responde a este correo.`,
    `— Equipo Taply`
  ].join('\n');

  const html = baseHtml(`
    <h1 style="margin:0 0 12px">¡Gracias, ${escapeHtml(first)}!</h1>
    <p style="margin:0 0 8px">Hemos recibido tu compra de <strong>${escapeHtml(String(qty))} NFC</strong>.</p>
    <p style="margin:0 0 8px">En breve te enviaremos la guía rápida y coordinamos el envío.</p>
    <p style="margin:0 0 8px">¿Dudas? Responde a este correo y te ayudamos.</p>
  `);

  return { subject, text, html };
}

function buildSubMail({ name, plan }) {
  const first = firstName(name);
  const subject = `Tu suscripción (${plan}) está activa ✅`;
  const text = [
    `Hola ${first},`,
    `Tu suscripción (${plan}) está activa.`,
    `Ahora te enviamos la guía rápida y configuramos tu panel.`,
    `Si necesitas algo, responde a este correo.`,
    `— Equipo Taply`
  ].join('\n');

  const html = baseHtml(`
    <h1 style="margin:0 0 12px">¡Suscripción activa!</h1>
    <p style="margin:0 0 8px">Hola ${escapeHtml(first)}, tu suscripción <strong>${escapeHtml(plan)}</strong> está activa.</p>
    <p style="margin:0 0 8px">Te enviaremos la guía rápida y dejaremos tu panel listo.</p>
    <p style="margin:0 0 8px">¿Dudas? Responde a este correo y te ayudamos.</p>
  `);

  return { subject, text, html };
}

async function sendMail({ to, subject, text, html }) {
  const msg = {
    to,
    from: FROM_EMAIL,
    subject,
    text,
    html,
    ...(REPLY_TO ? { replyTo: REPLY_TO } : {}),
    ...(BCC_EMAIL ? { bcc: BCC_EMAIL } : {})
  };
  try {
    await sgMail.send(msg);
    console.log('[mail] sent to', to, 'subject:', subject);
  } catch (e) {
    console.error('[mail] send error:', e?.response?.body || e?.message || e);
  }
}

function baseHtml(inner) {
  return `
  <div style="font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif; background:#0b0f1a; padding:24px">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background:#0e1424;border:1px solid rgba(255,255,255,.08);border-radius:16px;color:#e9eefc">
      <tr><td style="padding:20px 22px">
        <div style="font-weight:800;margin-bottom:10px">
          <span style="display:inline-block;width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,#00d4ff,#7c3aed);vertical-align:-6px;margin-right:8px"></span>
          Taply
        </div>
        ${inner}
        <hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:16px 0">
        <p style="margin:0;color:#9fb0c6;font-size:13px">Este correo se envió automáticamente tras tu compra. Si no reconoces esta acción, respóndenos.</p>
      </td></tr>
    </table>
  </div>
  `;
}

function firstName(full){ return String(full || '').trim().split(/\s+/)[0] || 'cliente'; }
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
