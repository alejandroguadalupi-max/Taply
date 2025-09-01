// TAPLY/lib/google-sheets.js
import { google } from 'googleapis';

const NFC_HEADERS = [
  'Fecha ISO','Modo','Session ID','Pedido',
  'Cliente','Email','Teléfono',
  'Cantidad NFC','Total (€)','Cupón',
  'Dirección','Ciudad','CP','País','Observaciones'
];

const SUB_HEADERS = [
  'Fecha ISO','Modo','Session ID','Suscripción ID',
  'Plan','Frecuencia','Primer cobro (€)','Moneda',
  'Estado','Periodo desde','Periodo hasta',
  'Cliente','Email','Teléfono','Cupón','Observaciones'
];

function getSheetsClient() {
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const key = (process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '').replace(/\\n/g, '\n');
  if (!email || !key) throw new Error('Missing GOOGLE_SERVICE_ACCOUNT_EMAIL or GOOGLE_SERVICE_ACCOUNT_KEY');

  const auth = new google.auth.JWT(email, null, key, ['https://www.googleapis.com/auth/spreadsheets']);
  return google.sheets({ version: 'v4', auth });
}

async function ensureHeaderRow({ sheets, spreadsheetId, tab, headers }) {
  const { data } = await sheets.spreadsheets.values.get({ spreadsheetId, range: `${tab}!A1:Z1` });
  const firstRow = data.values?.[0] || [];
  if (firstRow.length === 0) {
    await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `${tab}!A1:${String.fromCharCode(64 + headers.length)}1`,
      valueInputOption: 'RAW',
      requestBody: { values: [headers] }
    });
  }
}

/** Dedupe: usa Session ID (columna 3) */
async function appendIfNotExists({ sheets, spreadsheetId, tab, row, sessionId }) {
  // lee la columna C (Session ID)
  const read = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: `${tab}!C:C`
  });
  const values = read.data.values || [];
  const exists = values.some(r => (r[0] || '') === sessionId);
  if (exists) {
    console.log(`[sheets] skip duplicate: ${sessionId} in ${tab}`);
    return;
  }

  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${tab}!A:Z`,
    valueInputOption: 'USER_ENTERED',
    insertDataOption: 'INSERT_ROWS',
    requestBody: { values: [row] }
  });
  console.log(`[sheets] appended row to ${tab} for session ${sessionId}`);
}

export async function appendOrderToSheets({ type, session, full, event, subscription }) {
  try {
    const spreadsheetId = process.env.GOOGLE_SHEETS_ID;
    if (!spreadsheetId) throw new Error('Missing GOOGLE_SHEETS_ID');

    const sheets = getSheetsClient();
    const now = new Date().toISOString();
    const mode = session?.livemode ? 'live' : 'test';

    const cust = session?.customer_details || {};
    const name = cust?.name || '';
    const email = cust?.email || '';
    const phone = cust?.phone || '';

    const ship = session?.shipping_details || {};
    const addr = ship?.address || {};
    const addressLine = [addr?.line1, addr?.line2].filter(Boolean).join(', ');
    const city = addr?.city || '';
    const postal = addr?.postal_code || '';
    const country = addr?.country || '';

    const coupon =
      session?.total_details?.breakdown?.discounts?.[0]?.discount?.coupon?.name ||
      session?.total_details?.breakdown?.discounts?.[0]?.discount?.coupon?.id || '';

    if (type === 'nfc') {
      const tab = process.env.SHEETS_NFC_TAB || 'NFC';
      await ensureHeaderRow({ sheets, spreadsheetId, tab, headers: NFC_HEADERS });

      const items = full?.line_items?.data || [];
      const qty = items.reduce((a, it) => a + (it.quantity || 0), 0) || Number(session?.metadata?.qty || 1);
      const totalEUR = session?.amount_total != null ? session.amount_total / 100 : '';
      const paymentId =
        (typeof session.payment_intent === 'string' ? session.payment_intent : session.payment_intent?.id) ||
        (typeof session.payment_link === 'string' ? session.payment_link : '') || '';

      const row = [
        now, mode, session?.id || '', paymentId,
        name, email, phone,
        String(qty), totalEUR, coupon,
        addressLine, city, postal, country, ''
      ];
      await appendIfNotExists({ sheets, spreadsheetId, tab, row, sessionId: session?.id || '' });
      return;
    }

    // SUSCRIPCIÓN
    const tab = process.env.SHEETS_SUB_TAB || 'SUSCRIPCIONES';
    await ensureHeaderRow({ sheets, spreadsheetId, tab, headers: SUB_HEADERS });

    const it = full?.line_items?.data?.[0];
    const planName =
      it?.price?.product?.name ||
      it?.description ||
      `${session?.metadata?.tier || ''} ${session?.metadata?.frequency || ''}`.trim() ||
      '';

    const frequency = (session?.metadata?.frequency || '').toLowerCase() === 'annual' ? 'Anual' : 'Mensual';
    const firstCharge = session?.amount_total != null ? session.amount_total / 100 : '';
    const currency = (session?.currency || '').toUpperCase();
    const subId = (typeof session.subscription === 'string') ? session.subscription : session.subscription?.id || '';

    const status = subscription?.status || ''; // active / trialing / past_due …
    const periodStart = subscription?.current_period_start
      ? new Date(subscription.current_period_start * 1000).toISOString()
      : '';
    const periodEnd = subscription?.current_period_end
      ? new Date(subscription.current_period_end * 1000).toISOString()
      : '';

    const row = [
      now, mode, session?.id || '', subId,
      planName, frequency, firstCharge, currency,
      status, periodStart, periodEnd,
      name, email, phone, coupon, ''
    ];
    await appendIfNotExists({ sheets, spreadsheetId, tab, row, sessionId: session?.id || '' });
  } catch (e) {
    console.error('[sheets] append error:', e?.message || e);
  }
}
