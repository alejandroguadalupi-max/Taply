// /api/stripe-webhook.js
import Stripe from 'stripe';
import getRawBody from 'raw-body';

export const config = {
  api: { bodyParser: false } // 🔴 NECESARIO para verificar la firma
};

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    const raw = await getRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      // Aquí haz lo mínimo imprescindible y NO esperes tareas pesadas.
      // (envíos de email/WhatsApp mejor sin bloquear la respuesta)
      console.log('Pago completado:', session.id, session.mode);
    }

    // ✅ Responde rápido para no bloquear entregas de Stripe
    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('Webhook handler error', e);
    return res.status(500).send('Server error');
  }
}
