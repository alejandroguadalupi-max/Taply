// /api/sheets-auth-test.js
import { getSheetsClient, getSpreadsheetTitles } from './google-sheets.js';

export default async function handler(req, res) {
  try {
    const { email } = await getSheetsClient();
    const spreadsheetId = process.env.GOOGLE_SHEETS_ID;

    if (spreadsheetId) {
      const titles = await getSpreadsheetTitles(spreadsheetId);
      return res.status(200).json({
        ok: true,
        email,
        spreadsheetId,
        sheets: titles,
      });
    }

    return res.status(200).json({ ok: true, email, note: 'Sin GOOGLE_SHEETS_ID' });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
}
