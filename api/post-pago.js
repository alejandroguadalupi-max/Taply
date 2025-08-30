import Stripe from 'stripe';
import getRawBody from 'raw-body';
import twilio from 'twilio';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

  // 1) verificar firma
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

      // 2) expandir para ver items/plan
      const full = await stripe.checkout.sessions.retrieve(session.id, {
        expand: ['line_items.data.price.product']
      });

      // 3) datos cliente (nombre/teléfono)
      const d = session.customer_details || {};
      const name = d.name || 'cliente';
      let phone = d.phone || session?.shipping_details?.phone || null;

      if (!phone && session.customer) {
        try {
          const customer = await stripe.customers.retrieve(session.customer);
          phone = customer?.phone || null;
        } catch {}
      }
      phone = normalizePhone(phone);

      // 4) textos distintos
      let body = null;

      if (session.mode === 'payment' || session.metadata?.type === 'nfc') {
        const items = full.line_items?.data || [];
        const qty = items.reduce((acc, it) => acc + (it.quantity || 0), 0) || session.metadata?.qty || 1;
        body =
`¡Hola ${firstName(name)}! Soy de Taply 👋
Hemos recibido tu compra de ${qty} NFC ✅

En breve te escribo para confirmar el envío y preparar tu proyecto.
Si necesitas algo, responde a este WhatsApp.`;
      } else if (session.mode === 'subscription' || session.metadata?.type === 'subscription') {
        const item = full.line_items?.data?.[0];
        const planName =
          item?.price?.product?.name ||
          item?.description ||
          `${session.metadata?.tier || ''} ${session.metadata?.frequency || ''}`.trim() ||
          'tu suscripción';
        body =
`¡Hola ${firstName(name)}! Soy de Taply 👋
Tu suscripción (${planName}) está activa ✅

Ahora te envío la guía rápida y configuro tu panel.
Cualquier duda, respóndeme por aquí.`;
      }

      // 5) enviar WhatsApp
      if (phone && body) {
        await sendWhatsApp({ to: phone, body });
      } else {
        console.warn('No phone or body; skip WhatsApp. session:', session.id);
      }
    }

    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('post-pago handler error:', e);
    return res.status(500).send('Server error');
  }
}

/* helpers */
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
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_WHATSAPP_FROM) {
    console.warn('Missing Twilio env vars → skip WhatsApp'); return;
  }
  const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  const toAddr = to.startsWith('whatsapp:') ? to : `whatsapp:+${to}`;
  try {
    const msg = await client.messages.create({
      from: TWILIO_WHATSAPP_FROM, // 'whatsapp:+14155238886' (sandbox)
      to: toAddr,
      body
    });
    console.log('WhatsApp sent:', msg.sid);
  } catch (err) {
    console.error('Twilio send error:', err?.message || err);
  }
}
