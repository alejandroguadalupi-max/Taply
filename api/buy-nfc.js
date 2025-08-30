import Stripe from 'stripe';

// Lee el cuerpo JSON en funciones serverless de Vercel
async function readJson(req) {
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    const body = await readJson(req);
    const q = Number(body.quantity);

    if (!Number.isInteger(q) || q < 1 || q > 500) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_creation: 'always', // guardará los datos en un Customer

      line_items: [
        { price: process.env.PRICE_ID_NFC, quantity: q }
      ],

      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,

      // Teléfono nativo de Stripe (visible pero no estrictamente obligatorio)
      phone_number_collection: { enabled: true },

      // Dirección de envío OBLIGATORIA
      shipping_address_collection: {
        allowed_countries: ['ES'] // añade más si envías a otros países
      },

      // Campos personalizados OBLIGATORIOS
      custom_fields: [
        {
          key: 'business_name',
          label: { type: 'custom', custom: 'Nombre del negocio' },
          type: 'text',
          optional: false,
          text: { maximum_length: 120 }
        },
        {
          key: 'contact_name',
          label: { type: 'custom', custom: 'Nombre y apellidos de contacto' },
          type: 'text',
          optional: false,
          text: { maximum_length: 120 }
        },
        {
          key: 'contact_phone',
          label: { type: 'custom', custom: 'Teléfono de contacto (WhatsApp)' },
          type: 'text',
          optional: false,
          text: { maximum_length: 20 }
        }
      ],

      billing_address_collection: 'auto',

      // Mensajes en Checkout para remarcar el teléfono
      custom_text: {
        shipping_address: {
          message: 'Usaremos esta dirección para enviar tus dispositivos NFC.'
        },
        submit: {
          message: 'IMPORTANTE: te escribiremos por WhatsApp al teléfono de contacto para configurar Taply. Verifica que sea correcto.'
        }
      },

      // Identificar que es compra de NFC en el webhook
      metadata: { nfc_quantity: String(q) }
    });

    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error:', e);
    return res.status(500).json({ error: 'No se pudo crear el checkout' });
  }
}
