import { Resend } from "resend";

let cached = global._mailer;
if (!cached) cached = global._mailer = { client: null };

export function getTransporter() {
  if (cached.client) return cached.client;
  const resend = new Resend(process.env.RESEND_API_KEY);
  // sendMail() shim — all existing callers (api/contact.js, api/subscribe.js etc.) work unchanged
  cached.client = {
    sendMail: async ({ from, to, subject, html, text }) => {
      const replyTo = process.env.REPLY_TO_EMAIL;
      const { data, error } = await resend.emails.send({
        from, to, subject, html, text,
        ...(replyTo ? { reply_to: replyTo } : {})
      });
      if (error) throw new Error(`Resend error: ${JSON.stringify(error)}`);
      return data;
    }
  };
  return cached.client;
}

// ── Shared helpers ────────────────────────────────────────────────────────────
const SITE = 'https://www.fwfindia.org';
function _sup() { return process.env.REPLY_TO_EMAIL || process.env.SMTP_USER || 'info@fwfindia.org'; }
function _infoRow(label, value, bg = '#fff') {
  return `<tr style="background:${bg}"><td style="padding:11px 15px;color:#6b7280;font-weight:600;width:42%;border-bottom:1px solid #f1f5f9;font-size:13px">${label}</td><td style="padding:11px 15px;color:#111827;font-weight:700;border-bottom:1px solid #f1f5f9;font-size:13px">${value}</td></tr>`;
}
function _footer(accent = '#E87722') {
  return `<div style="background:#f8fafc;border-top:4px solid ${accent};padding:24px 32px;text-align:center;font-family:Arial,sans-serif">
    <p style="margin:0 0 6px;font-size:13px;color:#6b7280">Questions? Write to us at <a href="mailto:${_sup()}" style="color:${accent}">${_sup()}</a></p>
    <p style="margin:0;font-size:12px;color:#9ca3af">© ${new Date().getFullYear()} Foundris Welfare Foundation · <a href="${SITE}" style="color:${accent}">fwfindia.org</a></p>
  </div>`;
}

// ── Member welcome email ──────────────────────────────────────────────────────
export async function sendMemberWelcome({ name, email, memberId, password, mobile = '' }) {
  const transporter = getTransporter();
  const loginUrl = `${SITE}/member-login.html`;
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">
  <!-- Header -->
  <tr><td style="background:linear-gradient(135deg,#E87722 0%,#d4601a 100%);border-radius:12px 12px 0 0;padding:36px 32px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:28px;font-weight:800;letter-spacing:-0.5px">🎉 Welcome to FWF!</h1>
    <p style="margin:8px 0 0;color:rgba(255,255,255,0.88);font-size:15px">Your membership is confirmed</p>
  </td></tr>
  <!-- Body -->
  <tr><td style="background:#fff;padding:32px">
    <p style="margin:0 0 20px;font-size:16px;color:#374151">Dear <strong>${name}</strong>,</p>
    <p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.6">Welcome to the <strong>Foundris Welfare Foundation</strong> family! Your membership has been successfully activated. Below are your login credentials — please keep them safe.</p>
    <!-- Credentials box -->
    <div style="background:#fff7ed;border:2px solid #fed7aa;border-radius:10px;padding:20px 24px;margin:0 0 24px">
      <p style="margin:0 0 12px;font-size:13px;font-weight:700;color:#92400e;text-transform:uppercase;letter-spacing:.5px">Your Login Credentials</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border-radius:8px;overflow:hidden;border:1px solid #fde8c8">
        ${_infoRow('Member ID', `<span style="font-family:monospace;font-size:15px;color:#E87722">${memberId}</span>`, '#fff')}
        ${password ? _infoRow('Password', `<span style="font-family:monospace;font-size:15px;color:#E87722">${password}</span>`, '#fafafa') : ''}
        ${mobile ? _infoRow('Registered Mobile', mobile, '#fff') : ''}
      </table>
      <p style="margin:14px 0 0;font-size:12px;color:#b45309">⚠️ Please change your password after your first login for security.</p>
    </div>
    <!-- CTA -->
    <div style="text-align:center;margin:28px 0">
      <a href="${loginUrl}" style="display:inline-block;background:linear-gradient(135deg,#E87722,#d4601a);color:#fff;text-decoration:none;padding:14px 36px;border-radius:8px;font-size:16px;font-weight:700;letter-spacing:.3px">Login to Dashboard →</a>
    </div>
    <!-- Features list -->
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:10px 12px;background:#f9fafb;border-radius:8px;font-size:14px;color:#374151">✅ Track your project contributions</td>
      </tr><tr><td height="8"></td></tr>
      <tr>
        <td style="padding:10px 12px;background:#f9fafb;border-radius:8px;font-size:14px;color:#374151">✅ Manage your FWF wallet & earnings</td>
      </tr><tr><td height="8"></td></tr>
      <tr>
        <td style="padding:10px 12px;background:#f9fafb;border-radius:8px;font-size:14px;color:#374151">✅ Access skill development resources</td>
      </tr>
    </table>
  </td></tr>
  <!-- Footer -->
  <tr><td>${_footer('#E87722')}</td></tr>
</table>
</td></tr></table>
</body></html>`;

  return transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: `🎉 Welcome to FWF — Your Member ID: ${memberId}`,
    html
  });
}