import Stripe from 'stripe';
import getRawBody from 'raw-body';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const sig = req.headers['stripe-signature'];

    const raw = await getRawBody(req); // cuerpo sin parsear
    const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      console.log('Pago completado:', session.id, session.mode);
      // Aquí lanza procesos asíncronos (email/WhatsApp/DB). No bloquees la respuesta.
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('stripe webhook error:', err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || 'unknown'}`);
  }
}
