// /api/stripe-webhook.js
import Stripe from 'stripe';
import { sendEmail } from './_utils.js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405; return res.end('Method Not Allowed');
  }

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    const raw = await readRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Firma inválida:', err.message);
    res.statusCode = 400; return res.end(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;

      const email = s.customer_details?.email;
      const total = s.amount_total;
      const currency = (s.currency || 'eur').toUpperCase();
      const mode = s.mode;

      const fmt = (cents, curr) => new Intl.NumberFormat('es-ES',{style:'currency',currency:curr}).format((cents||0)/100);

      if (email) {
        const html = `
          <div style="font-family:Inter,Arial,sans-serif;color:#0b0f1a">
            <h2>¡Gracias! Tu ${mode === 'subscription' ? 'suscripción' : 'pago'} se ha completado.</h2>
            <p><strong>Importe:</strong> ${fmt(total, currency)}</p>
            <p>En cualquier momento puedes gestionar tu suscripción desde tu área personal.</p>
          </div>`;
        await sendEmail({ to: email, subject: 'Confirmación de pago Taply', html });
      }
    }

    res.statusCode = 200; return res.end(JSON.stringify({ received: true }));
  } catch (e) {
    console.error('⚠️ Webhook handler error:', e);
    res.statusCode = 500; return res.end('Server error');
  }
}
