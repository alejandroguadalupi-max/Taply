// /api/stripe-webhook.js
import Stripe from 'stripe';

// Leer RAW body para verificar firma de Stripe
async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Enviar email con Resend (sin SDK, usando fetch)
async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.FROM_EMAIL || 'Taply <no-reply@taply.app>';
  if (!apiKey || !from || !to) {
    console.log('sendEmail: faltan env vars o destinatario; se omite.');
    return;
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from, to, subject, html })
  });

  if (!res.ok) {
    const txt = await res.text();
    console.error('Resend error:', res.status, txt);
  }
}

export const config = {
  api: { bodyParser: false } // MUY IMPORTANTE para verificar firma
};

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    const raw = await readRawBody(req);
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Firma inválida:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;

      // ¿Es compra de NFC? (lo marcamos en buy-nfc.js con metadata.nfc_quantity)
      const isNfcOrder = !!s.metadata?.nfc_quantity;

      // Custom fields que pedimos en buy-nfc.js
      const fields = Array.isArray(s.custom_fields) ? s.custom_fields : [];
      const cf = (key) => fields.find(f => f.key === key)?.text?.value || '';
      const businessName = cf('business_name');
      const contactName  = cf('contact_name');
      const contactPhone = cf('contact_phone') || s.customer_details?.phone || '';

      // Datos del cliente
      const email   = s.customer_details?.email || '';
      const total   = s.amount_total; // céntimos
      const currency = (s.currency || 'eur').toUpperCase();
      const qty     = s.metadata?.nfc_quantity || '';
      const shipping = s.shipping_details; // {name, address...}

      const fmtMoney = (cents, curr) =>
        new Intl.NumberFormat('es-ES', { style: 'currency', currency: curr || 'EUR' })
          .format((cents || 0) / 100);

      // Dirección para el email
      const addr = shipping?.address;
      const shippingHtml = addr ? [
        shipping?.name,
        addr?.line1,
        addr?.line2,
        `${addr?.postal_code || ''} ${addr?.city || ''}`.trim(),
        addr?.state,
        addr?.country
      ].filter(Boolean).join('<br>') : '';

      const subject = isNfcOrder
        ? 'Confirmación de pedido Taply (NFC)'
        : 'Confirmación de pago Taply';

      const html = `
        <div style="font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0b0f1a">
          <h2 style="margin:0 0 10px">¡Gracias por tu ${isNfcOrder ? 'pedido de NFC' : 'pago'}!</h2>
          ${businessName ? `<p style="margin:0 0 6px"><strong>Negocio:</strong> ${businessName}</p>` : ''}
          ${contactName  ? `<p style="margin:0 0 6px"><strong>Contacto:</strong> ${contactName}</p>` : ''}
          ${isNfcOrder && qty ? `<p style="margin:0 0 6px"><strong>NFC pedidos:</strong> ${qty}</p>` : ''}
          <p style="margin:0 0 6px"><strong>Total:</strong> ${fmtMoney(total, currency)}</p>
          ${contactPhone ? `<p style="margin:0 0 6px"><strong>Teléfono:</strong> ${contactPhone}</p>` : ''}

          ${shippingHtml ? `
            <div style="margin:12px 0 10px">
              <strong>Dirección de envío:</strong><br>${shippingHtml}
            </div>` : ''}

          <p style="margin:14px 0 0">
            En breve te contactaremos por WhatsApp para configurar Taply y coordinar el envío.
          </p>
          <p style="margin:6px 0 0">Si necesitas ayuda, responde a este correo.</p>
        </div>
      `;

      if (email) {
        await sendEmail({ to: email, subject, html });
      }
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('⚠️ Error en handler webhook:', err);
    return res.status(500).send('Webhook handler failed');
  }
}
