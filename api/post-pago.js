// /api/post-pago.js  (ajusta el nombre de archivo a tu ruta real)
import Stripe from 'stripe';
import getRawBody from 'raw-body';

export const config = { api: { bodyParser: false } };

const RESEND_URL = 'https://api.resend.com/emails';

// Enviar correo con Resend sin SDK
async function sendEmail({ to, subject, html }) {
  const resp = await fetch(RESEND_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.FROM_EMAIL,             // p.ej. "Taply <hello@tu-dominio.com>"
      to: Array.isArray(to) ? to : [to],        // destinatarios
      subject,
      html,
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.error('Resend error', resp.status, text);
  }
}

// Lee el text de un custom_field
function getTextField(session, key) {
  const f = (session.custom_fields || []).find(x => x.key === key);
  return f?.text?.value || '';
}

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
    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;

        // Datos clave (porque activaste phone_number_collection y shipping address)
        const email   = s.customer_details?.email || '';
        const phone   = s.customer_details?.phone || '';   // WhatsApp de contacto
        const mode    = s.mode; // 'payment' (NFC) o 'subscription'
        const negocio = getTextField(s, 'business_name');
        const contacto= getTextField(s, 'contact_name');

        // Dirección de envío
        const ship    = s.shipping_details;
        const addressLine = ship?.address ? [
          ship.address.line1,
          ship.address.line2,
          `${ship.address.postal_code || ''} ${ship.address.city || ''}`.trim(),
          ship.address.state,
          ship.address.country
        ].filter(Boolean).join(', ') : '';

        // Si en la creación de sesión guardaste cantidad en metadata (recomendado en buy-nfc.js)
        const nfcQty = s.metadata?.nfc_quantity || '—';

        const subject = mode === 'payment'
          ? 'Pedido recibido — Dispositivos NFC de Taply'
          : 'Suscripción activada — Taply';

        const html = `
          <div style="font-family:Inter,system-ui,sans-serif;color:#0b0f1a">
            <h2>¡Gracias por tu ${mode === 'payment' ? 'compra' : 'suscripción'}!</h2>
            <p>Hemos recibido tu pedido correctamente.</p>

            <h3>Datos recibidos</h3>
            <ul>
              <li><strong>Email:</strong> ${email || '—'}</li>
              <li><strong>Teléfono (WhatsApp):</strong> ${phone || '—'}</li>
              <li><strong>Nombre del negocio:</strong> ${negocio || '—'}</li>
              <li><strong>Persona de contacto:</strong> ${contacto || '—'}</li>
              ${mode === 'payment' ? `<li><strong>Unidades NFC:</strong> ${nfcQty}</li>` : ''}
              ${addressLine ? `<li><strong>Dirección de envío:</strong> ${addressLine}</li>` : ''}
            </ul>

            <p>
              <strong>El teléfono es importante:</strong> te contactaremos por
              <strong>WhatsApp a ${phone || 'el número indicado'}</strong> para configurar todo.
            </p>

            <p>Si necesitas algo, responde a este correo.</p>

            <p style="margin-top:18px">— Equipo Taply</p>
          </div>
        `;

        // Enviar al cliente y copia a ti
        const to = email
          ? [email, process.env.NOTIFY_EMAIL || process.env.FROM_EMAIL]
          : [process.env.NOTIFY_EMAIL || process.env.FROM_EMAIL];

        await sendEmail({ to, subject, html });

        console.log('Email enviado. session:', s.id, 'mode:', mode);
        break;
      }

      case 'payment_intent.succeeded':
      case 'invoice.payment_succeeded': {
        // Opcional: lógica extra (renovaciones, etc.)
        break;
      }

      default:
        console.log('Evento no manejado:', event.type);
    }

    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('Webhook handler error', e);
    return res.status(500).send('Server error');
  }
}
