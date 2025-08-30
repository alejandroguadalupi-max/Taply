// /api/stripe-webhook.js
// TAPLY/api/post-pago.js
import Stripe from 'stripe';
import getRawBody from 'raw-body';
import twilio from 'twilio';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

  let event;
  try {
    const sig = req.headers['stripe-signature'];
    const raw = await getRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Stripe signature error:', err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || 'invalid signature'}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // Expandimos para ver items/planes
      const full = await stripe.checkout.sessions.retrieve(session.id, {
        expand: ['line_items.data.price.product']
      });

      // Datos del cliente
      const details = session.customer_details || {};
      const name = details.name || 'cliente';
      let phone = details.phone || session?.shipping_details?.phone || null;

      // Fallback al Customer si existe
      if (!phone && session.customer) {
        try {
          const customer = await stripe.customers.retrieve(session.customer);
          phone = customer?.phone || null;
        } catch {}
      }
      phone = normalizePhone(phone);

      // Mensaje según tipo
      let body;
      if (session.mode === 'payment') {
        // NFC (pago único)
        const items = full.line_items?.data || [];
        const qty = items.reduce((acc, it) => acc + (it.quantity || 0), 0) || 1;
        body =
          `¡Hola ${firstName(name)}! Soy de Taply 👋\n` +
          `Hemos recibido tu compra de ${qty} NFC ✅\n\n` +
          `En breve te escribo para confirmar el envío y preparar tu proyecto. ` +
          `Si necesitas algo, responde a este WhatsApp.`;
      } else if (session.mode === 'subscription') {
        // Suscripción
        const item = full.line_items?.data?.[0];
        const planName =
          item?.price?.product?.name ||
          item?.description ||
          'tu suscripción';
        body =
          `¡Hola ${firstName(name)}! Soy de Taply 👋\n` +
          `Tu suscripción (${planName}) está activa ✅\n\n` +
          `Ahora te envío la guía rápida y configuro tu panel. ` +
          `Cualquier duda, respóndeme por aquí.`;
      }

      if (phone && body) {
        await sendWhatsApp({ to: phone, body });
      } else {
        console.warn('No phone or body for session', session.id);
      }
    }

    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('post-pago handler error:', e);
    return res.status(500).send('Server error');
  }
}

/* Helpers */
function firstName(full) {
  return String(full || '').trim().split(/\s+/)[0] || 'cliente';
}
function normalizePhone(raw) {
  if (!raw) return null;
  const digits = String(raw).replace(/\D+/g, '');
  if (digits.startsWith('00')) return digits.slice(2);
  if (digits.length >= 10 && digits.length <= 15) return digits;
  const prefix = (process.env.WHATSAPP_DEFAULT_PREFIX || '').replace(/\D+/g, '');
  return prefix ? prefix + digits : digits;
}
async function sendWhatsApp({ to, body }) {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_WHATSAPP_FROM) {
    console.warn('Missing Twilio env vars → skip WhatsApp'); return;
  }
  const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  const toAddr = to.startsWith('whatsapp:') ? to : `whatsapp:+${to}`;
  try {
    const msg = await client.messages.create({
      from: process.env.TWILIO_WHATSAPP_FROM,
      to: toAddr,
      body
    });
    console.log('WhatsApp sent:', msg.sid);
  } catch (err) {
    console.error('Twilio send error:', err?.message || err);
  }
}
