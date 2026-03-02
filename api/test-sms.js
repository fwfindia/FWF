/**
 * DEBUG ONLY — Test MSG91 SMS OTP
 * DELETE this file after debugging is done!
 * Usage: POST /api/test-sms  { "mobile": "9999999999", "key": "fwf-debug-2026" }
 */
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { mobile, key } = req.body || {};
  if (key !== 'fwf-debug-2026') return res.status(403).json({ error: 'Forbidden' });
  if (!mobile) return res.status(400).json({ error: 'mobile required' });

  const authKey    = process.env.MSG91_AUTH_KEY;
  const templateId = process.env.MSG91_OTP_TEMPLATE_FORGOT || process.env.MSG91_OTP_TEMPLATE_ID;

  // Report env var status
  const envStatus = {
    MSG91_AUTH_KEY:           authKey ? `SET (${authKey.slice(0,6)}***)` : 'MISSING ❌',
    MSG91_OTP_TEMPLATE_FORGOT: process.env.MSG91_OTP_TEMPLATE_FORGOT || 'MISSING ❌',
    MSG91_OTP_TEMPLATE_ID:    process.env.MSG91_OTP_TEMPLATE_ID || 'MISSING ❌',
    TWILIO_ACCOUNT_SID:       process.env.TWILIO_ACCOUNT_SID ? 'SET' : 'not set',
  };

  if (!authKey || !templateId) {
    return res.status(500).json({ error: 'MSG91 env vars missing', envStatus });
  }

  const otp    = '123456';
  const fmt    = (m) => { const d = String(m).replace(/\D/g,''); return d.startsWith('91') && d.length===12 ? d : `91${d.slice(-10)}`; };
  const mobile_fmt = fmt(mobile);

  try {
    const response = await fetch('https://control.msg91.com/api/v5/otp', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authkey': authKey },
      body:    JSON.stringify({ template_id: templateId, mobile: mobile_fmt, otp })
    });

    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    return res.json({
      ok:          data?.type === 'success',
      msg91_status: response.status,
      msg91_response: data,
      envStatus,
      mobile_formatted: mobile_fmt,
      template_used: templateId
    });
  } catch (e) {
    return res.status(500).json({ error: e.message, envStatus });
  }
}
