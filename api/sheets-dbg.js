// TAPLY/api/sheets-dbg.js
import { getSpreadsheetInfo, ensureHeaderRow, appendRow } from '../lib/google-sheets.js';

const NFC_TAB   = process.env.SHEETS_NFC_TAB || 'NFC';
const SUB_TAB   = process.env.SHEETS_SUB_TAB || 'SUSCRIPCIONES';

const NFC_HEADERS = ['fecha', 'session_id', 'mode', 'email', 'name', 'city', 'postal_code', 'country', 'qty', 'amount_total', 'currency', 'coupon', 'payment_id'];
const SUB_HEADERS = ['fecha', 'session_id', 'sub_id', 'planName', 'frequency', 'firstCharge', 'status', 'periodStart', 'periodEnd', 'currency', 'email', 'name'];

export default async function handler(req, res) {
  try {
    const action = String(req.query.action || '').toLowerCase();

    if (action === 'env') {
      return res.status(200).json({
        ok: true,
        env: {
          GOOGLE_SERVICE_ACCOUNT_EMAIL: !!process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
          GOOGLE_SERVICE_ACCOUNT_KEY: (process.env.GOOGLE_SERVICE_ACCOUNT_KEY ? 'present' : 'missing'),
          GOOGLE_SHEETS_ID: !!process.env.GOOGLE_SHEETS_ID,
          SHEETS_NFC_TAB: NFC_TAB,
          SHEETS_SUB_TAB: SUB_TAB,
        },
        hint: 'Si falta algo, corrígelo en Vercel → Environment Variables y redeploy.',
      });
    }

    if (action === 'auth' || action === 'list') {
      const info = await getSpreadsheetInfo();
      return res.status(200).json({ ok: true, info });
    }

    if (action === 'headers') {
      await ensureHeaderRow(NFC_TAB, NFC_HEADERS);
      await ensureHeaderRow(SUB_TAB, SUB_HEADERS);
      return res.status(200).json({ ok: true, set: [NFC_TAB, SUB_TAB] });
    }

    if (action === 'append-nfc') {
      await ensureHeaderRow(NFC_TAB, NFC_HEADERS);
      const now = new Date().toISOString();
      const fake = ['test'];
      await appendRow(NFC_TAB, [
        now, 'debug_session', 'payment', 'test@mail.com', 'Cliente Test',
        'Madrid', '28001', 'ES', 3, 150, 'EUR', '', 'pi_debug'
      ]);
      return res.status(200).json({ ok: true, appended: NFC_TAB });
    }

    if (action === 'append-sub') {
      await ensureHeaderRow(SUB_TAB, SUB_HEADERS);
      const now = new Date().toISOString();
      await appendRow(SUB_TAB, [
        now, 'debug_session', 'sub_123', 'Taply Plan Medio', 'Mensual', 35, 'active',
        new Date(Date.now()-1000).toISOString(), new Date(Date.now()+2592e6).toISOString(),
        'EUR', 'test@mail.com', 'Cliente Test'
      ]);
      return res.status(200).json({ ok: true, appended: SUB_TAB });
    }

    return res.status(200).json({
      ok: true,
      usage: [
        '/api/sheets-dbg?action=env',
        '/api/sheets-dbg?action=auth',
        '/api/sheets-dbg?action=list',
        '/api/sheets-dbg?action=headers',
        '/api/sheets-dbg?action=append-nfc',
        '/api/sheets-dbg?action=append-sub',
      ],
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
}
