const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

initializeApp();
const db = getFirestore();

// Stored via: firebase functions:secrets:set RESEND_API_KEY
// Never hardcode the real key here — this just declares which secret name
// to pull in at deploy/runtime.
const RESEND_API_KEY = defineSecret('RESEND_API_KEY');

const CODE_TTL_MINUTES = 10;
const CODE_LENGTH = 6;

function generateCode() {
  // 6-digit numeric code, zero-padded (e.g. "042819")
  const n = Math.floor(Math.random() * 10 ** CODE_LENGTH);
  return String(n).padStart(CODE_LENGTH, '0');
}

// Only these emails are allowed to request a code at all — anyone else's
// request is silently rejected before a code is even generated. Add/remove
// emails here as needed (all lowercase).
const ALLOWED_EMAILS = [
  'zhuangriyuan@gmail.com',
  // 'your-second-email@example.com',
  // 'your-third-email@example.com',
];

// --- 1. Request a code: generates one, stores it (hashed-ish via Firestore
// doc keyed by email, not exposed to the client), emails it via Resend. ---
exports.requestVerificationCode = onCall({ secrets: [RESEND_API_KEY] }, async (request) => {
  const email = (request.data && request.data.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    throw new HttpsError('invalid-argument', '邮箱地址不对');
  }
  if (!ALLOWED_EMAILS.includes(email)) {
    throw new HttpsError('permission-denied', '这个邮箱不在允许登录的名单里');
  }

  const code = generateCode();
  const expiresAt = Date.now() + CODE_TTL_MINUTES * 60 * 1000;

  // One doc per email, overwritten each time a new code is requested —
  // requesting a new code invalidates any previous unused one.
  await db.collection('verificationCodes').doc(email).set({
    code,
    expiresAt,
    attempts: 0,
    createdAt: FieldValue.serverTimestamp(),
  });

  const emailRes = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY.value()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: '行程规划 <onboarding@resend.dev>',
      to: [email],
      subject: `你的登录验证码：${code}`,
      html: `<div style="font-family: sans-serif; padding: 24px;">
        <h2 style="margin-bottom: 8px;">登录验证码</h2>
        <p style="color: #666;">${CODE_TTL_MINUTES} 分钟内有效，输入下面这串数字完成登录：</p>
        <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px; margin: 16px 0;">${code}</p>
        <p style="color: #999; font-size: 12px;">如果不是你本人操作，忽略这封邮件即可。</p>
      </div>`,
    }),
  });

  if (!emailRes.ok) {
    const errText = await emailRes.text();
    console.error('Resend send failed:', errText);
    throw new HttpsError('internal', '验证码邮件发送失败，请稍后重试');
  }

  return { sent: true };
});

// --- 2. Verify the code: checks it against Firestore, then mints a
// Firebase custom token the client can sign in with (signInWithCustomToken). ---
exports.verifyCodeAndSignIn = onCall(async (request) => {
  const email = (request.data && request.data.email || '').trim().toLowerCase();
  const code = (request.data && request.data.code || '').trim();
  if (!email || !code) {
    throw new HttpsError('invalid-argument', '邮箱或验证码缺失');
  }

  const ref = db.collection('verificationCodes').doc(email);
  const snap = await ref.get();
  if (!snap.exists) {
    throw new HttpsError('not-found', '还没有请求过验证码，或者已经用过了');
  }

  const data = snap.data();

  if (Date.now() > data.expiresAt) {
    await ref.delete();
    throw new HttpsError('deadline-exceeded', '验证码已过期，请重新发送');
  }

  // Basic brute-force guard: 5 wrong tries and the code is dead, request a new one.
  if (data.attempts >= 5) {
    await ref.delete();
    throw new HttpsError('resource-exhausted', '错误次数太多，请重新发送验证码');
  }

  if (data.code !== code) {
    await ref.update({ attempts: FieldValue.increment(1) });
    throw new HttpsError('permission-denied', '验证码不对');
  }

  // Correct — consume the code (single use) and mint a sign-in token.
  await ref.delete();

  // Look up by email — this correctly finds any account that already
  // exists for this address (e.g. from earlier testing with a different
  // sign-in method), instead of guessing a uid and colliding with it.
  let userRecord;
  try {
    userRecord = await getAuth().getUserByEmail(email);
  } catch (e) {
    userRecord = await getAuth().createUser({ email });
  }

  const token = await getAuth().createCustomToken(userRecord.uid);
  return { token };
});

// --- 3. Delete a trip: allowed if the caller is the authenticated owner, OR
// if they supply the trip's correct editKey (the same "anyone with the edit
// link can delete" model the original InstantDB ruleParams check had).
// Firestore security rules can't inspect a "proof of key" on a delete
// operation the way they can on an update (there's no request.resource.data
// to compare against), so this goes through a Cloud Function with admin
// access instead. ---
exports.deleteTripWithKey = onCall(async (request) => {
  const tripId = (request.data && request.data.tripId || '').trim();
  const editKey = (request.data && request.data.editKey || '').trim();
  if (!tripId) {
    throw new HttpsError('invalid-argument', '缺少 tripId');
  }

  const ref = db.collection('trips').doc(tripId);
  const snap = await ref.get();
  if (!snap.exists) {
    return { deleted: false }; // already gone — treat as success
  }
  const trip = snap.data();

  const isOwner = request.auth && request.auth.uid && request.auth.uid === trip.ownerUid;
  const hasEditKey = trip.editSecret && editKey && trip.editSecret === editKey;

  if (!isOwner && !hasEditKey) {
    throw new HttpsError('permission-denied', '没有权限删除这个行程');
  }

  await ref.delete();
  return { deleted: true };
});
