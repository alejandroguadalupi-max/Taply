import Stripe from 'stripe';
import getRawBody from 'raw-body';
import twilio from 'twilio';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  // 0) Clave y modo coherentes (evita 500 si mezclas test/live)
  const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || '';
  if (!STRIPE_KEY) return res.status(500).json({ error: 'missing_stripe_key' });

  const stripe = new Stripe(STRIPE_KEY);

  // 1) Verificar firma
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    const raw = await getRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
    // Sugerencia: comprueba coherencia de clave vs modo del evento
    const live = !!event.livemode;
    if (live && !STRIPE_KEY.startsWith('sk_live_')) {
      console.warn('[post-pago] live event with test key');
    }
    if (!live && !STRIPE_KEY.startsWith('sk_test_')) {
      console.warn('[post-pago] test event with live key — retrieve may fail');
    }
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

      // 3) Datos del cliente
      const d = session.customer_details || {};
      const name = d.name || 'cliente';
      let phone = d.phone || session?.shipping_details?.phone || null;

      if (!phone && session.customer) {
        try {
          const customer = await stripe.customers.retrieve(session.customer);
          phone = customer?.phone || null;
        } catch (e) {
          console.warn('[post-pago] no phone in customer');
        }
      }
      phone = normalizePhone(phone);

      // 4) Mensajes según tipo con *fallbacks* por si no hay line_items
      let body = null;
      if (session.mode === 'payment' || session.metadata?.type === 'nfc') {
        const items = full?.line_items?.data || [];
        const qty = items.reduce((acc, it) => acc + (it.quantity || 0), 0) || session.metadata?.qty || 1;
        body =
`¡Hola ${firstName(name)}! Soy de Taply 👋
Hemos recibido tu compra de ${qty} NFC ✅

En breve te escribo para confirmar el envío y preparar tu proyecto.
Si necesitas algo, responde a este WhatsApp.`;
      } else if (session.mode === 'subscription' || session.metadata?.type === 'subscription') {
        const it = full?.line_items?.data?.[0];
        const planName =
          it?.price?.product?.name ||
          it?.description ||
          `${session.metadata?.tier || ''} ${session.metadata?.frequency || ''}`.trim() ||
          'tu suscripción';
        body =
`¡Hola ${firstName(name)}! Soy de Taply 👋
Tu suscripción (${planName}) está activa ✅

Ahora te envío la guía rápida y configuro tu panel.
Cualquier duda, respóndeme por aquí.`;
      }

      // 5) Enviar WhatsApp (si no hay teléfono, usa número de test si lo pones)
      const toFinal = phone || (process.env.TEST_WHATSAPP_TO || '').trim();
      if (!toFinal) {
        console.warn('[post-pago] no phone & no TEST_WHATSAPP_TO → skip send');
      } else if (body) {
        await sendWhatsApp({ to: toFinal, body, label: phone ? 'user' : 'TEST' });
      }
    }

    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('[post-pago] handler error:', e);
    return res.status(500).json({ error: 'handler_error', detail: e?.message || String(e) });
  }
}

/* ===== Helpers ===== */
function firstName(full) { return String(full || '').trim().split(/\s+/)[0] || 'cliente'; }
function normalizePhone(raw) {
  if (!raw) return null;
  let d = String(raw).replace(/\D+/g, '');
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length >= 10 && d.length <= 15) return d;
  const p = (process.env.WHATSAPP_DEFAULT_PREFIX || '').replace(/\D+/g, '');
  return p ? p + d : d;
}
async function sendWhatsApp({ to, body, label='user' }) {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_WHATSAPP_FROM) {
    console.warn('[post-pago] missing Twilio envs → skip'); return;
  }
  const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  const toAddr = to.startsWith('whatsapp:') ? to : `whatsapp:${to.startsWith('+') ? to : `+${to}`}`;
  const msg = await client.messages.create({ from: TWILIO_WHATSAPP_FROM, to: toAddr, body });
  console.log(`[post-pago] WhatsApp sent (${label}):`, msg.sid);
}
