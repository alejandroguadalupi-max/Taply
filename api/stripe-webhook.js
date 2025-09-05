// api/stripe-webhook.js
import Stripe from 'stripe';
import getRawBody from 'raw-body';

export const config = { api: { bodyParser: false }, runtime: 'nodejs' };

// Envío básico por SendGrid (opcional). Se recomienda dejar los emails de cliente al flujo "post-pago" para evitar duplicados.
async function sendEmail({to, subject, html}) {
  if(!process.env.SENDGRID_API_KEY || !process.env.EMAIL_FROM || !to) return;
  const { default: sgMail } = await import('@sendgrid/mail');
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  await sgMail.send({
    to,
    from: process.env.EMAIL_FROM,
    replyTo: process.env.EMAIL_REPLY_TO || process.env.EMAIL_FROM,
    subject,
    text: html.replace(/<[^>]+>/g,' ').slice(0,1000),
    html
  });
}

let stripeSingleton = null;
function stripeClient(){
  if(!stripeSingleton){
    if(!process.env.STRIPE_SECRET_KEY) throw new Error('Missing STRIPE_SECRET_KEY');
    stripeSingleton = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
  }
  return stripeSingleton;
}

function toInt(v){ const n=parseInt(v,10); return Number.isFinite(n)?n:0; }

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  if(!process.env.STRIPE_WEBHOOK_SECRET){
    console.error('STRIPE_WEBHOOK_SECRET missing');
    return res.status(500).send('Config error');
  }

  try {
    const stripe = stripeClient();
    const sig  = req.headers['stripe-signature'];
    const raw  = await getRawBody(req);
    let event;
    try{
      event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
    }catch(err){
      console.error('Invalid signature', err?.message || err);
      return res.status(400).send(`Webhook Error: ${err?.message || 'invalid_signature'}`);
    }

    async function upsertCustomerMeta(customerId, patch){
      try{
        const cust = await stripe.customers.retrieve(customerId);
        const meta = Object.assign({}, cust.metadata || {});
        await stripe.customers.update(customerId, { metadata: { ...meta, ...patch }});
      }catch(e){ console.error('upsert meta err', e?.message || e); }
    }

    async function nfcQtyFromCheckoutSession(sessionId){
      if (!process.env.PRICE_ID_NFC) return 0;
      try{
        const full = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
        const items = full.line_items?.data || [];
        return items.reduce((acc, it) => acc + ((it.price?.id === process.env.PRICE_ID_NFC) ? (it.quantity || 0) : 0), 0);
      }catch(e){ console.error('expand line_items err', e?.message || e); return 0; }
    }

    switch(event.type){

      // === Checkout completado (pago NFC o suscripción inicial)
      case 'checkout.session.completed': {
        const cs = event.data.object;
        const email = cs.customer_details?.email || null;

        // guarda teléfono/nombre si Stripe lo devuelve
        if (cs.customer) {
          try{
            const patch = {};
            if (cs.customer_details?.phone) patch.phone = cs.customer_details.phone;
            if (cs.customer_details?.name)  patch.name  = cs.customer_details.name;
            if (Object.keys(patch).length) await stripe.customers.update(cs.customer, patch);
          }catch(e){ console.error('customer update err', e?.message || e); }
        }

        // si es compra NFC, suma al contador
        if (cs.mode === 'payment' && cs.customer) {
          const addQty = await nfcQtyFromCheckoutSession(cs.id);
          if (addQty > 0) {
            try{
              const cust = await stripe.customers.retrieve(cs.customer);
              const prev = toInt(cust?.metadata?.taply_nfc_qty);
              await upsertCustomerMeta(cs.customer, { taply_nfc_qty: String(prev + addQty) });
            }catch(e){ console.error('update nfc qty err', e?.message || e); }
          }
        }

        // Email de administración (el de cliente se envía desde /api/post-pago para evitar duplicados)
        if(process.env.EMAIL_FROM){
          const amountText = (cs.amount_total!=null && cs.currency) ? `${(cs.amount_total/100).toFixed(2)} ${cs.currency.toUpperCase()}` : '-';
          const title = cs.mode === 'subscription' ? 'Suscripción activada' : 'Pago recibido';
          await sendEmail({ to: process.env.EMAIL_FROM, subject: `Taply — ${title}`, html: `<p>${title}</p><p>Cliente: ${email || '—'}</p><p>Importe: ${amountText}</p>` });
        }
        break;
      }

      // === Cambios en la suscripción
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const price = sub.items?.data?.[0]?.price || null;
        const patch = {
          taply_sub_status: sub.status || '',
          taply_sub_price: price?.id || '',
          taply_sub_price_nickname: price?.nickname || '',
          taply_sub_interval: price?.recurring?.interval || '',
          taply_sub_current_period_start: String(sub.current_period_start || ''),
          taply_sub_current_period_end: String(sub.current_period_end || ''),
          taply_sub_schedule: sub.schedule || ''
        };
        if(sub.customer) await upsertCustomerMeta(sub.customer, patch);
        break;
      }

      default:
        // otros eventos: 200 OK
        break;
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('stripe webhook error:', err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || 'unknown'}`);
  }
}
