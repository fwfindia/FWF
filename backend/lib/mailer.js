import { Resend } from 'resend';

let cached = global._backendMailer;
if (!cached) cached = global._backendMailer = { client: null };

// ─── shared helpers ───────────────────────────────────────────────────────────
const SITE = 'https://www.fwfindia.org';
const SUPPORT_EMAIL = () => process.env.REPLY_TO_EMAIL || process.env.SUPPORT_EMAIL || process.env.SMTP_USER || 'info@fwfindia.org';

function emailFooter(accentColor = '#E87722') {
  return `
  <div style="background:#f9fafb;padding:20px 32px;border-radius:0 0 14px 14px;border:1px solid #e5e7eb;border-top:none;text-align:center">
    <p style="color:#6b7280;font-size:12px;margin:0 0 4px">
      <strong style="color:${accentColor}">Foundris Welfare Foundation (FWF)</strong>
    </p>
    <p style="color:#9ca3af;font-size:11px;margin:0">
      <a href="${SITE}" style="color:${accentColor};text-decoration:none">www.fwfindia.org</a>
      &nbsp;·&nbsp;
      <a href="mailto:${SUPPORT_EMAIL()}" style="color:${accentColor};text-decoration:none">${SUPPORT_EMAIL()}</a>
      &nbsp;·&nbsp; This is a system-generated email.
    </p>
  </div>`;
}

function infoRow(label, value, bg = '#fff') {
  return `<tr style="background:${bg}">
    <td style="padding:12px 16px;color:#6b7280;font-weight:600;width:42%;border-bottom:1px solid #f1f5f9">${label}</td>
    <td style="padding:12px 16px;color:#111827;font-weight:700;border-bottom:1px solid #f1f5f9">${value}</td>
  </tr>`;
}
// ─────────────────────────────────────────────────────────────────────────────

export function getTransporter() {
  if (cached.client) return cached.client;
  const resend = new Resend(process.env.RESEND_API_KEY);
  // Expose sendMail() shim so all existing call sites work unchanged
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

/**
 * Send 80G tax receipt email to donor.
 * @param {Object} params
 */
export async function send80GReceipt({ donationId, name, email, pan, address, amount, paymentId, date }) {
  const transporter = getTransporter();
  const formattedAmount = Number(amount).toLocaleString('en-IN');
  const formattedDate = new Date(date).toLocaleDateString('en-IN', {
    day: '2-digit', month: 'long', year: 'numeric'
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: `FWF — 80G Tax Exemption Receipt #${donationId}`,
    html: `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:620px;margin:0 auto;background:#fff">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#ff416c,#ff4f81);padding:30px 32px 24px;border-radius:12px 12px 0 0;text-align:center">
        <div style="font-size:36px;margin-bottom:8px">🏛️</div>
        <h1 style="color:#fff;margin:0;font-size:22px;font-weight:700">80G Tax Exemption Receipt</h1>
        <p style="color:rgba(255,255,255,0.85);margin:4px 0 0;font-size:14px">Foundris Welfare Foundation</p>
      </div>

      <!-- Receipt Box -->
      <div style="padding:32px;border-left:1px solid #f0e0e0;border-right:1px solid #f0e0e0">
        <p style="color:#374151;font-size:15px;margin-bottom:24px">
          Dear <strong>${name}</strong>,<br><br>
          Thank you for your generous contribution to Foundris Welfare Foundation (FWF).
          This is your official <strong>80G tax exemption receipt</strong> as per the Income Tax Act, 1961.
          Please retain this for your tax filing records.
        </p>

        <!-- Receipt Details Table -->
        <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px">
          <tr style="background:#fdf2f4">
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;width:45%;border-bottom:1px solid #f3e5e8">Receipt No.</td>
            <td style="padding:12px 16px;color:#111827;font-weight:700;border-bottom:1px solid #f3e5e8">${donationId}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">Date</td>
            <td style="padding:12px 16px;color:#111827;border-bottom:1px solid #f3e5e8">${formattedDate}</td>
          </tr>
          <tr style="background:#fdf2f4">
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">Donor Name</td>
            <td style="padding:12px 16px;color:#111827;font-weight:600;border-bottom:1px solid #f3e5e8">${name}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">PAN Number</td>
            <td style="padding:12px 16px;color:#111827;font-family:monospace;letter-spacing:2px;font-weight:600;border-bottom:1px solid #f3e5e8">${pan.toUpperCase()}</td>
          </tr>
          <tr style="background:#fdf2f4">
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">Address</td>
            <td style="padding:12px 16px;color:#111827;border-bottom:1px solid #f3e5e8">${address}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">Mode of Payment</td>
            <td style="padding:12px 16px;color:#111827;border-bottom:1px solid #f3e5e8">Online (Razorpay)</td>
          </tr>
          <tr style="background:#fdf2f4">
            <td style="padding:12px 16px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3e5e8">Transaction ID</td>
            <td style="padding:12px 16px;color:#111827;font-family:monospace;font-size:13px;border-bottom:1px solid #f3e5e8">${paymentId}</td>
          </tr>
          <tr style="background:linear-gradient(135deg,#fff0f3,#ffe5ec)">
            <td style="padding:14px 16px;color:#be123c;font-weight:700;font-size:16px">Donation Amount</td>
            <td style="padding:14px 16px;color:#be123c;font-weight:900;font-size:20px">₹${formattedAmount}</td>
          </tr>
        </table>

        <!-- 80G Declaration -->
        <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:10px;padding:18px 20px;margin-bottom:24px">
          <p style="color:#166534;font-size:13px;margin:0;line-height:1.6">
            <strong>📜 80G Declaration:</strong><br>
            This receipt certifies that the above donation has been received by <strong>Foundris Welfare Foundation</strong>
            and is eligible for tax deduction under Section 80G of the Income Tax Act, 1961.
            The organization is registered and approved for 80G exemption.
            Donors can claim <strong>50% deduction</strong> on the donated amount while computing taxable income.
          </p>
        </div>

        <!-- How to claim -->
        <div style="background:#f8faff;border:1px solid #dbe3f7;border-radius:10px;padding:16px 20px;margin-bottom:24px">
          <p style="color:#374151;font-size:13px;margin:0;line-height:1.6">
            <strong>💡 How to claim deduction:</strong><br>
            1. Keep this receipt safe for your records<br>
            2. Mention your PAN (${pan.toUpperCase()}) when filing your ITR<br>
            3. Declare this donation under "80G Donations" in your tax return<br>
            4. For any queries, email us at <a href="mailto:${process.env.SMTP_USER}" style="color:#ff416c">${process.env.SMTP_USER}</a>
          </p>
        </div>
      </div>

      <!-- Footer -->
      <div style="background:#fdf2f4;padding:20px 32px;border-radius:0 0 12px 12px;border:1px solid #f0e0e0;border-top:none;text-align:center">
        <p style="color:#9ca3af;font-size:12px;margin:0 0 4px">
          <strong style="color:#ff416c">Foundris Welfare Foundation (FWF)</strong>
        </p>
        <p style="color:#9ca3af;font-size:11px;margin:0">
          <a href="https://www.fwfindia.org" style="color:#ff416c;text-decoration:none">www.fwfindia.org</a>
          &nbsp;·&nbsp; This is a system-generated receipt. No signature required.
        </p>
      </div>
    </div>`
  });
}

// ─── 1. MEMBER WELCOME + CREDENTIALS ─────────────────────────────────────────
/**
 * Send welcome email to a newly registered member with login credentials.
 */
export async function sendMemberWelcome({ name, email, memberId, password, mobile = '', receiptUrl = null }) {
  if (!email) return;
  const transporter = getTransporter();
  const date = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: `🎉 Welcome to FWF! Your Member ID: ${memberId}`,
    html: `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:620px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#E87722,#f59e0b);padding:36px 32px 28px;text-align:center">
        <div style="font-size:48px;margin-bottom:10px">🎉</div>
        <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800">Welcome to FWF!</h1>
        <p style="color:rgba(255,255,255,.85);margin:6px 0 0;font-size:15px">Foundris Welfare Foundation — Empowering Women</p>
      </div>

      <!-- Body -->
      <div style="padding:32px;border:1px solid #e5e7eb;border-top:none">
        <p style="color:#374151;font-size:15px;line-height:1.7;margin-bottom:24px">
          Dear <strong>${name}</strong>,<br><br>
          Congratulations! 🙌 Your membership with <strong>Foundris Welfare Foundation (FWF)</strong> has been successfully activated on <strong>${date}</strong>.<br>
          Below are your login credentials. Please keep them safe and confidential.
        </p>

        <!-- Credentials Box -->
        <div style="background:linear-gradient(135deg,#fff7ed,#ffedd5);border:2px solid #fed7aa;border-radius:12px;padding:22px 24px;margin-bottom:24px">
          <p style="margin:0 0 14px;font-size:13px;font-weight:700;color:#9a3412;text-transform:uppercase;letter-spacing:.5px">🔐 Your Login Credentials</p>
          <table style="width:100%;border-collapse:collapse;font-size:15px">
            ${infoRow('Member ID', `<span style="font-family:monospace;font-size:18px;color:#C2410C;font-weight:900">${memberId}</span>`, '#fff8f0')}
            ${infoRow('Password', `<span style="font-family:monospace;font-size:16px;color:#b45309;letter-spacing:1px">${password}</span>`, '#fff')}
            ${mobile ? infoRow('Mobile', mobile, '#fff8f0') : ''}
            ${infoRow('Login URL', `<a href="${SITE}/login" style="color:#E87722;font-weight:700">${SITE}/login</a>`, '#fff')}
          </table>
        </div>

        <!-- What you can do -->
        <div style="background:#f9fafb;border-radius:12px;padding:20px 22px;margin-bottom:24px">
          <p style="margin:0 0 12px;font-size:13px;font-weight:800;color:#374151">🚀 What you can do as a Member:</p>
          <ul style="margin:0;padding-left:18px;color:#6b7280;font-size:13px;line-height:2">
            <li>View your Wallet & Points balance</li>
            <li>Refer friends & earn reward points</li>
            <li>Access Social Book, Events & Quizzes</li>
            <li>Browse the Marketplace & Skill Training</li>
            <li>Raise support tickets anytime</li>
          </ul>
        </div>

        <!-- CTA -->
        <div style="text-align:center;margin-bottom:24px">
          <a href="${SITE}/login" style="display:inline-block;background:linear-gradient(135deg,#E87722,#f59e0b);color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:800;letter-spacing:.3px">
            Login to Dashboard →
          </a>
        </div>

        ${receiptUrl ? `
        <div style="text-align:center;margin:0 0 20px">
          <a href="${receiptUrl}" style="display:inline-block;background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;text-decoration:none;padding:13px 28px;border-radius:10px;font-weight:700;font-size:14px">📄 View / Download Receipt</a>
          <p style="color:#9ca3af;font-size:11px;margin:8px 0 0">Your membership receipt — printable as PDF. Valid permanently.</p>
        </div>` : ''}

        <div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:12px 16px">
          <p style="margin:0;color:#92400e;font-size:12px;font-weight:600">
            🔒 <strong>Security Tip:</strong> Change your password after first login from your profile settings. Never share your credentials with anyone.
          </p>
        </div>
      </div>

      ${emailFooter('#E87722')}
    </div>`
  });
}

// ─── 2. SUPPORTER WELCOME + CREDENTIALS ──────────────────────────────────────
/**
 * Send welcome email to a newly registered supporter with login credentials.
 */
export async function sendSupporterWelcome({ name, email, supporterId, password, project = '' }) {
  if (!email) return;
  const transporter = getTransporter();
  const date = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: `🤝 Welcome FWF Supporter! Your ID: ${supporterId}`,
    html: `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:620px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#059669,#10b981);padding:36px 32px 28px;text-align:center">
        <div style="font-size:48px;margin-bottom:10px">🤝</div>
        <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800">Welcome, ${name}!</h1>
        <p style="color:rgba(255,255,255,.85);margin:6px 0 0;font-size:15px">You are now an FWF Supporter — Thank you!</p>
      </div>

      <!-- Body -->
      <div style="padding:32px;border:1px solid #e5e7eb;border-top:none">
        <p style="color:#374151;font-size:15px;line-height:1.7;margin-bottom:24px">
          Dear <strong>${name}</strong>,<br><br>
          Your support means the world to us! 💚 You have been registered as a <strong>Supporter</strong> with Foundris Welfare Foundation on <strong>${date}</strong>.
          ${project ? `<br>Project of interest: <strong>${project}</strong>` : ''}
          <br>Your login credentials are below — please save them.
        </p>

        <!-- Credentials Box -->
        <div style="background:linear-gradient(135deg,#f0fdf4,#dcfce7);border:2px solid #86efac;border-radius:12px;padding:22px 24px;margin-bottom:24px">
          <p style="margin:0 0 14px;font-size:13px;font-weight:700;color:#14532d;text-transform:uppercase;letter-spacing:.5px">🔐 Your Login Credentials</p>
          <table style="width:100%;border-collapse:collapse;font-size:15px">
            ${infoRow('Supporter ID', `<span style="font-family:monospace;font-size:18px;color:#059669;font-weight:900">${supporterId}</span>`, '#f0fff8')}
            ${infoRow('Password', `<span style="font-family:monospace;font-size:16px;color:#047857;letter-spacing:1px">${password}</span>`, '#fff')}
            ${infoRow('Login URL', `<a href="${SITE}/login" style="color:#10b981;font-weight:700">${SITE}/login</a>`, '#f0fff8')}
          </table>
        </div>

        <!-- What you can do -->
        <div style="background:#f9fafb;border-radius:12px;padding:20px 22px;margin-bottom:24px">
          <p style="margin:0 0 12px;font-size:13px;font-weight:800;color:#374151">🌱 What you can do as a Supporter:</p>
          <ul style="margin:0;padding-left:18px;color:#6b7280;font-size:13px;line-height:2">
            <li>Share your volunteer work on Social Book</li>
            <li>Participate in Events, Tasks & Activities</li>
            <li>Join Fund Raiser Quiz Games</li>
            <li>Submit support tickets & get help</li>
          </ul>
        </div>

        <!-- CTA -->
        <div style="text-align:center;margin-bottom:24px">
          <a href="${SITE}/login" style="display:inline-block;background:linear-gradient(135deg,#059669,#10b981);color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:800">
            Go to Supporter Dashboard →
          </a>
        </div>

        <div style="background:#dcfce7;border:1px solid #86efac;border-radius:8px;padding:12px 16px">
          <p style="margin:0;color:#14532d;font-size:12px;font-weight:600">
            🔒 <strong>Security Tip:</strong> Change your password after first login. Never share your credentials with anyone.
          </p>
        </div>
      </div>

      ${emailFooter('#10b981')}
    </div>`
  });
}

// ─── 3. DONATION TRANSACTION CONFIRMATION ────────────────────────────────────
/**
 * Send donation receipt / thank-you email to donor (always, regardless of 80G).
 */
export async function sendDonationConfirmation({ name, email, amount, donationId, paymentId, recurring = false, pointsEarned = 0, receiptUrl = null }) {
  if (!email) return;
  const transporter = getTransporter();
  const formatted = Number(amount).toLocaleString('en-IN');
  const date = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: `💝 Donation Received ₹${formatted} — Thank You, ${name}!`,
    html: `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:620px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#be185d,#ec4899);padding:36px 32px 28px;text-align:center">
        <div style="font-size:48px;margin-bottom:10px">💝</div>
        <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800">Thank You, ${name}!</h1>
        <p style="color:rgba(255,255,255,.85);margin:6px 0 0;font-size:15px">Your donation has been received successfully</p>
      </div>

      <!-- Body -->
      <div style="padding:32px;border:1px solid #e5e7eb;border-top:none">
        <p style="color:#374151;font-size:15px;line-height:1.7;margin-bottom:24px">
          Dear <strong>${name}</strong>,<br><br>
          We have received your ${recurring ? '<strong>monthly recurring</strong> ' : ''}donation of <strong>₹${formatted}</strong> on <strong>${date}</strong>.
          Your generosity directly supports women's skills, welfare & self-employment programs. 🙏
        </p>

        <!-- Amount Highlight -->
        <div style="background:linear-gradient(135deg,#fdf2f8,#fce7f3);border:2px solid #f9a8d4;border-radius:12px;padding:22px 24px;margin-bottom:22px;text-align:center">
          <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:#9d174d;text-transform:uppercase;letter-spacing:.5px">${recurring ? '🔄 Monthly Recurring Donation' : '💝 Donation Amount'}</p>
          <p style="margin:0;font-size:42px;font-weight:900;color:#be185d">₹${formatted}</p>
          ${recurring ? '<p style="margin:6px 0 0;font-size:12px;color:#9d174d;font-weight:600">This amount will be auto-debited every month</p>' : ''}
        </div>

        <!-- Transaction Details -->
        <div style="margin-bottom:24px">
          <p style="margin:0 0 10px;font-size:13px;font-weight:800;color:#374151">📋 Transaction Details</p>
          <table style="width:100%;border-collapse:collapse;font-size:14px;border:1px solid #f1f5f9;border-radius:10px;overflow:hidden">
            ${infoRow('Donation ID', `<span style="font-family:monospace;font-weight:800;color:#be185d">${donationId}</span>`, '#fdf2f8')}
            ${infoRow('Payment ID', `<span style="font-family:monospace;font-size:12px">${paymentId}</span>`, '#fff')}
            ${infoRow('Date', date, '#fdf2f8')}
            ${infoRow('Mode', 'Online (Razorpay)', '#fff')}
            ${infoRow('Type', recurring ? '🔄 Monthly Subscription' : '✅ One-time Payment', '#fdf2f8')}
            ${pointsEarned ? infoRow('Reward Points', `<span style="color:#E87722;font-weight:900">+${Math.round(pointsEarned)} pts</span> credited to your wallet`, '#fff') : ''}
          </table>
        </div>

        <!-- Impact -->
        <div style="background:#f9fafb;border-radius:12px;padding:18px 22px;margin-bottom:24px">
          <p style="margin:0 0 10px;font-size:13px;font-weight:800;color:#374151">🌸 Your Impact:</p>
          <ul style="margin:0;padding-left:18px;color:#6b7280;font-size:13px;line-height:2">
            <li>Skill training & livelihood programs for women</li>
            <li>Educational support & scholarships</li>
            <li>Health camps & community welfare activities</li>
            <li>Entrepreneurship support for women self-help groups</li>
          </ul>
        </div>

        <!-- CTA -->
        ${receiptUrl ? `
        <div style="text-align:center;margin-bottom:16px">
          <a href="${receiptUrl}" style="display:inline-block;background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;text-decoration:none;padding:12px 26px;border-radius:10px;font-weight:700;font-size:14px">📄 View / Download Receipt</a>
          <p style="color:#9ca3af;font-size:11px;margin:8px 0 0">Click to view, print or save as PDF. Valid permanently.</p>
        </div>` : ''}
        <div style="text-align:center;margin-bottom:20px">
          <a href="${SITE}/donation" style="display:inline-block;background:linear-gradient(135deg,#be185d,#ec4899);color:#fff;text-decoration:none;padding:12px 30px;border-radius:50px;font-size:14px;font-weight:800">
            Donate Again →
          </a>
        </div>

        <p style="color:#9ca3af;font-size:12px;text-align:center;margin:0">
          ${receiptUrl ? '' : 'If you need an 80G tax receipt, please contact us at <a href="mailto:${SUPPORT_EMAIL()}" style="color:#be185d">${SUPPORT_EMAIL()}</a> with your PAN details.'}
          ${receiptUrl ? 'For an 80G tax certificate, please contact us at <a href="mailto:${SUPPORT_EMAIL()}" style="color:#be185d">${SUPPORT_EMAIL()}</a> with your PAN details.' : ''}
        </p>
      </div>

      ${emailFooter('#be185d')}
    </div>`
  });
}

// ─── 4. ADMIN NOTIFICATION ────────────────────────────────────────────────────
/**
 * Send a simple admin notification email.
 */
export async function sendAdminAlert({ subject, rows = [], extra = '' }) {
  const to = process.env.ADMIN_EMAIL || process.env.SMTP_USER;
  if (!to) return;
  const transporter = getTransporter();
  const tableRows = rows.map(([k, v]) =>
    `<tr><td style="padding:8px 12px;color:#6b7280;font-weight:600;font-size:13px;border-bottom:1px solid #f1f5f9;width:40%">${k}</td><td style="padding:8px 12px;color:#111827;font-weight:700;font-size:13px;border-bottom:1px solid #f1f5f9">${v}</td></tr>`
  ).join('');

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: `[FWF Admin] ${subject}`,
    html: `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb">
      <div style="background:#1e293b;padding:16px 20px">
        <h2 style="color:#fff;margin:0;font-size:16px;font-weight:700">🔔 ${subject}</h2>
        <p style="color:#94a3b8;margin:3px 0 0;font-size:12px">${new Date().toLocaleString('en-IN')}</p>
      </div>
      <div style="padding:20px">
        ${tableRows ? `<table style="width:100%;border-collapse:collapse;border:1px solid #f1f5f9;border-radius:8px;overflow:hidden">${tableRows}</table>` : ''}
        ${extra ? `<div style="margin-top:14px;padding:12px;background:#f8fafc;border-radius:8px;font-size:13px;color:#374151">${extra}</div>` : ''}
      </div>
    </div>`
  });
}
