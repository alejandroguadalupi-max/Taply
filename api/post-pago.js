// /api/stripe-webhook.js
import Stripe from 'stripe';
import getRawBody from 'raw-body';

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
      // Aquí tienes los datos del cliente:
      // const email = session.customer_details?.email;
      // const phone = session.customer_details?.phone; // si activaste phone_number_collection
      // const mode = session.mode; // 'payment' o 'subscription'

      // Aquí en el futuro: enviar WhatsApp / email.
      console.log('Pago completado:', session.id, session.mode);
    }

    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('Webhook handler error', e);
    return res.status(500).send('Server error');
  }
}
