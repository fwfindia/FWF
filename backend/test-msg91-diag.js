const AUTH_KEY = '497148Arak0XxtpLER69a2e3cdP1';
const MOBILE   = '919580118412';

// 1) Check if OTP verify works (OTP 123456 was sent in last test)
const v = await fetch(`https://control.msg91.com/api/v5/otp/verify?mobile=${MOBILE}&otp=123456&authkey=${AUTH_KEY}`);
console.log('\n[OTP verify 123456]', v.status, await v.text());

// 2) Send a fresh OTP and immediately check if it can be verified
const s = await fetch('https://control.msg91.com/api/v5/otp', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authkey': AUTH_KEY },
  body: JSON.stringify({ template_id: '69aa74240eaf63c70f00c802', mobile: MOBILE, otp: '999888' })
});
console.log('\n[OTP send 999888]', s.status, await s.text());
await new Promise(r => setTimeout(r, 2000));

const v2 = await fetch(`https://control.msg91.com/api/v5/otp/verify?mobile=${MOBILE}&otp=999888&authkey=${AUTH_KEY}`);
console.log('[OTP verify 999888]', v2.status, await v2.text());

// 3) Check WA template vars (send 1 var vs 5 vars — which one does template have?)
const waBody = (vars) => JSON.stringify({
  integrated_number: '15558189243',
  content_type: 'template',
  payload: {
    messaging_product: 'whatsapp', type: 'template',
    template: {
      name: 'thank_you_for_donation_fwf',
      language: { code: 'en', policy: 'deterministic' },
      namespace: '08e35bb9_f5fd_49ae_b619_803d3b606cac',
      to_and_components: [{ to: [MOBILE], components: vars }]
    }
  }
});

// Test with only the template's 1st body variable
const wa = await fetch('https://api.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'authkey': AUTH_KEY },
  body: waBody({ body_1: { type: 'text', value: 'Rahul Kumar' } })
});
console.log('\n[WA 1-var test]', wa.status, await wa.text());
