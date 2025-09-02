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

function parseIntSafe(v, def=0){ const n = parseInt(v,10); return Number.isFinite(n) ? n : def; }

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  try {
    if(!process.env.STRIPE_SECRET_KEY) return res.status(500).send('Missing STRIPE_SECRET_KEY');
    if(!process.env.STRIPE_WEBHOOK_SECRET) return res.status(500).send('Missing STRIPE_WEBHOOK_SECRET');

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const sig = req.headers['stripe-signature'];
    const raw = await getRawBody(req);
    const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);

    // Helper: suma cuántos NFC hay en los line_items (por PRICE_ID_NFC)
    async function sumNfcFromSession(cs){
      if (!process.env.PRICE_ID_NFC) return 0;
      const full = await stripe.checkout.sessions.retrieve(cs.id, { expand: ['line_items'] });
      const items = full.line_items?.data || [];
      return items.reduce((acc, it) => {
        const isNfc = it.price?.id === process.env.PRICE_ID_NFC;
        return acc + (isNfc ? (it.quantity || 0) : 0);
      }, 0);
    }

    async function upsertCustomerMeta(customerId, patchMeta){
      const cust = await stripe.customers.retrieve(customerId);
      const meta = Object.assign({}, cust.metadata || {});
      const newMeta = Object.assign(meta, patchMeta);
      await stripe.customers.update(customerId, { metadata: newMeta });
    }

    if (event.type === 'checkout.session.completed') {
      const cs = event.data.object; // Checkout Session
      const email = cs.customer_details?.email || null;
      const title = cs.mode === 'subscription' ? 'Suscripción activada' : 'Pago recibido';

      // Actualiza teléfono/nombre en Stripe si vienen del checkout
      try{
        if (cs.customer) {
          const patch = {};
          if (cs.customer_details?.phone) patch.phone = cs.customer_details.phone;
          if (cs.customer_details?.name)  patch.name  = cs.customer_details.name;
          if (Object.keys(patch).length) await stripe.customers.update(cs.customer, patch);
        }
      }catch(e){ console.error('customer update from checkout err', e?.message || e); }

      // Si es compra NFC (pago único), suma a taply_nfc_qty
      if (cs.mode === 'payment' && cs.customer) {
        try{
          const addQty = await sumNfcFromSession(cs);
          if (addQty > 0) {
            const cust = await stripe.customers.retrieve(cs.customer);
            const prev = parseIntSafe(cust?.metadata?.taply_nfc_qty, 0);
            await upsertCustomerMeta(cs.customer, { taply_nfc_qty: String(prev + addQty) });
          }
        }catch(e){ console.error('sum NFC error', e?.message || e); }
      }

      // Emails
      const amountText = (cs.amount_total!=null && cs.currency) ? `${(cs.amount_total/100).toFixed(2)} ${cs.currency.toUpperCase()}` : '-';
      const html = `
        <h2>${title}</h2>
        <p>Gracias por tu compra en Taply.</p>
        <p>Importe: ${amountText}</p>
      `;
      if(email) await sendEmail({ to: email, subject: `Taply — ${title}`, html });
      if(process.env.EMAIL_FROM) await sendEmail({ to: process.env.EMAIL_FROM, subject: `Taply — ${title}`, html: `<p>${title}</p><p>Cliente: ${email || '—'}</p>` });
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('stripe webhook error:', err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || 'unknown'}`);
  }
}

