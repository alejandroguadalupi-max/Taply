// api/stripe-webhooks.js
import Stripe from 'stripe';
import getRawBody from 'raw-body';

export const config = {
  api: { bodyParser: false } // NECESARIO para raw-body
};

async function sendEmail({to, subject, html}) {
  if(!process.env.SENDGRID_API_KEY || !process.env.EMAIL_FROM) return;
  const { default: sgMail } = await import('@sendgrid/mail');
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  await sgMail.send({
    to,
    from: process.env.EMAIL_FROM,
    replyTo: process.env.EMAIL_REPLY_TO || process.env.EMAIL_FROM,
    subject,
    text: html.replace(/<[^>]+>/g,' '),
    html
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  try {
    if(!process.env.STRIPE_SECRET_KEY) return res.status(500).send('Missing STRIPE_SECRET_KEY');
    if(!process.env.STRIPE_WEBHOOK_SECRET) return res.status(500).send('Missing STRIPE_WEBHOOK_SECRET');

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const sig = req.headers['stripe-signature'];
    const raw = await getRawBody(req);
    const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);

    if (event.type === 'checkout.session.completed') {
      const cs = event.data.object; // Checkout Session
      const email = cs.customer_details?.email || null;
      const isSub = cs.mode === 'subscription';
      const title = isSub ? 'Suscripción activada' : 'Pago recibido';
      const html = `
        <h2>${title}</h2>
        <p>Gracias por tu compra en Taply.</p>
        <p>Importe: ${cs.amount_total ? (cs.amount_total/100).toFixed(2) + ' ' + (cs.currency||'').toUpperCase() : '-'}</p>
      `;
      if(email) await sendEmail({ to: email, subject: `Taply — ${title}`, html });
      // Aviso interno
      if(process.env.EMAIL_FROM) await sendEmail({ to: process.env.EMAIL_FROM, subject: `Taply — ${title}`, html: `<p>${title}</p><p>Cliente: ${email || '—'}</p>` });
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('stripe webhook error:', err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || 'unknown'}`);
  }
}
