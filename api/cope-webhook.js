// api/cope-webhook.js
//
// Receives Cope's signed webhook events and grants course access the moment
// a payment actually completes. This is the ONLY authoritative source of
// enrollment for external-checkout courses — the /welcome redirect page is
// purely cosmetic, per Cope's own docs.
//
// Written in CommonJS (require/module.exports) to match this project's
// existing Vercel serverless functions.

const crypto = require('crypto');
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

function normalizePrivateKey(raw) {
  if (!raw) return '';
  let key = raw.trim();
  if (
    (key.startsWith('"') && key.endsWith('"')) ||
    (key.startsWith("'") && key.endsWith("'"))
  ) {
    key = key.slice(1, -1);
  }
  key = key.replace(/\\n/g, '\n');
  return key.trim();
}

function getFirebaseAdmin() {
  if (!getApps().length) {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
      const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
      const serviceAccount = JSON.parse(json);
      initializeApp({ credential: cert(serviceAccount) });
      return getFirestore();
    }

    const privateKey = normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY);
    if (!privateKey.includes('BEGIN PRIVATE KEY')) {
      throw new Error(
        'FIREBASE_PRIVATE_KEY does not look like a valid PEM key after normalization. ' +
        'Strongly recommended: switch to FIREBASE_SERVICE_ACCOUNT_BASE64 instead (see setup notes).'
      );
    }
    initializeApp({
      credential: cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: privateKey,
      }),
    });
  }
  return getFirestore();
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyCopeSignature(rawBody, signatureHeader, signingSecret) {
  if (!signatureHeader) return { ok: false, reason: 'Missing signature header' };

  const parts = {};
  signatureHeader.split(',').forEach((pair) => {
    const [k, v] = pair.split('=');
    parts[k] = v;
  });
  const timestamp = parts.t;
  const providedSig = parts.v1;

  if (!timestamp || !providedSig) {
    return { ok: false, reason: 'Malformed signature header' };
  }

  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (ageSeconds > 300) {
    return { ok: false, reason: 'Signature timestamp too old' };
  }

  const expectedSig = crypto
    .createHmac('sha256', signingSecret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');

  const expectedBuf = Buffer.from(expectedSig, 'hex');
  const providedBuf = Buffer.from(providedSig, 'hex');

  const sigMatches =
    expectedBuf.length === providedBuf.length &&
    crypto.timingSafeEqual(expectedBuf, providedBuf);

  if (!sigMatches) return { ok: false, reason: 'Signature mismatch' };
  return { ok: true };
}

function extractLeadId(event) {
  const data = event.data || {};
  return (
    data.client_reference_id ||
    (data.cart && data.cart.client_reference_id) ||
    (data.order && data.order.client_reference_id) ||
    (data.checkout && data.checkout.client_reference_id) ||
    (data.metadata && data.metadata.client_reference_id) ||
    null
  );
}

// Tries several common places a payment processor might put the paid
// amount. Cope's exact payload shape may not match every path here, so
// this is defensive — if none of these hit, the caller falls back to the
// course's listed price so revenue reporting is never silently zero.
function extractPaidAmount(event) {
  const data = event.data || {};
  const candidates = [
    data.amount,
    data.amount_total,
    data.total,
    data.cart && data.cart.amount,
    data.cart && data.cart.total,
    data.order && data.order.amount,
    data.order && data.order.total,
    data.checkout && data.checkout.amount,
    data.metadata && data.metadata.amount,
  ];
  for (const c of candidates) {
    const n = parseFloat(c);
    if (!isNaN(n) && n > 0) return n;
  }
  return null;
}

async function getOrCreateAuthUser(auth, lead) {
  try {
    const existing = await auth.getUserByEmail(lead.email);
    return { uid: existing.uid, isNew: false };
  } catch (e) {
    if (e.code !== 'auth/user-not-found') throw e;
  }
  const tempPassword = crypto.randomBytes(24).toString('hex');
  const newUser = await auth.createUser({
    email: lead.email,
    password: tempPassword,
    displayName: lead.name || undefined,
  });
  return { uid: newUser.uid, isNew: true };
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    console.error('Cope webhook: failed to read request body', e);
    return res.status(400).json({ error: 'Could not read request body' });
  }

  const signatureHeader =
    req.headers['x-webhook-signature'] || req.headers['x-cope-signature'];

  const signingSecret = process.env.COPE_WEBHOOK_SIGNING_SECRET;

  if (!signingSecret) {
    console.error('COPE_WEBHOOK_SIGNING_SECRET is not set in environment variables.');
    return res.status(500).json({ error: 'Server misconfigured: missing webhook signing secret.' });
  }

  const verification = verifyCopeSignature(rawBody, signatureHeader, signingSecret);

  if (!verification.ok) {
    console.warn('Cope webhook signature rejected:', verification.reason);
    return res.status(400).json({ error: verification.reason });
  }

  let event;
  try {
    event = JSON.parse(rawBody.toString('utf8'));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  if (event.message && event.message.toLowerCase().includes('test webhook')) {
    console.log('Cope test webhook received and verified successfully.');
    return res.status(200).json({ ok: true, note: 'Test event verified.' });
  }

  const eventId = req.headers['x-cope-event-id'] || event.id || `${Date.now()}`;
  const eventType = event.type || '';

  let db;
  try {
    db = getFirebaseAdmin();
  } catch (e) {
    console.error('Cope webhook: Firebase Admin init failed', e);
    return res.status(500).json({ error: 'Firebase Admin initialization failed: ' + e.message });
  }

  try {
    const dedupeRef = db.collection('processedWebhookEvents').doc(String(eventId));
    const alreadyProcessed = await dedupeRef.get();
    if (alreadyProcessed.exists) {
      return res.status(200).json({ ok: true, note: 'Already processed, skipped.' });
    }

    const isPaymentSuccess =
      eventType.includes('order.completed') || eventType.includes('payment.sale.succeeded');

    if (!isPaymentSuccess) {
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false });
      return res.status(200).json({ ok: true, note: 'Event type not actioned.' });
    }

    const leadId = extractLeadId(event);
    if (!leadId) {
      console.error('Cope webhook: could not find client_reference_id in payload', JSON.stringify(event.data));
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false, error: 'no leadId found' });
      return res.status(200).json({ ok: true, note: 'No leadId found in payload — logged for review.' });
    }

    const leadRef = db.collection('leads').doc(leadId);
    const leadSnap = await leadRef.get();

    if (!leadSnap.exists) {
      console.error('Cope webhook: lead not found for id', leadId);
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false, error: 'lead not found' });
      return res.status(200).json({ ok: true, note: 'Lead not found — logged for review.' });
    }

    const lead = leadSnap.data();

    // Resolve the amount actually paid. Prefer whatever Cope's payload
    // tells us directly; fall back to the course's current listed price so
    // the admin revenue report is never silently zero for a real sale.
    let paidAmount = extractPaidAmount(event);
    let amountSource = 'webhook_payload';
    let courseDoc = null;
    if (lead.courseId) {
      const courseSnap = await db.collection('courses').doc(lead.courseId).get();
      if (courseSnap.exists) courseDoc = courseSnap.data();
    }
    if (paidAmount === null) {
      paidAmount = (courseDoc && courseDoc.priceUSD) || 0;
      amountSource = 'course_price_fallback';
    }

    const auth = getAuth();
    let uid, isNewUser;
    try {
      const result = await getOrCreateAuthUser(auth, lead);
      uid = result.uid;
      isNewUser = result.isNew;
    } catch (e) {
      console.error('Cope webhook: failed to get/create auth user for', lead.email, e);
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false, error: 'auth user creation failed: ' + e.message });
      return res.status(200).json({ ok: true, note: 'Auth user creation failed — logged for review.' });
    }

    await db.collection('users').doc(uid).set({
      email: lead.email,
      name: lead.name || '',
      role: 'student',
      createdAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    const enrollmentRef = await db.collection('enrollments').add({
      courseId: lead.courseId,
      courseTitle: lead.courseTitle || '',
      instructorId: lead.instructorId || null,
      uid: uid,
      studentEmail: lead.email,
      studentName: lead.name,
      leadId: leadId,
      paymentProcessor: 'cope',
      subscriptionStatus: 'active',
      failedPayments: 0,
      copeEventId: eventId,
      paidAmount: paidAmount,
      currency: 'USD',
      amountSource: amountSource,
      enrolledAt: FieldValue.serverTimestamp(),
    });

    await leadRef.update({ status: 'converted', uid: uid, enrollmentId: enrollmentRef.id, convertedAt: FieldValue.serverTimestamp() });

    if (lead.courseId) {
      await db.collection('courses').doc(lead.courseId).update({
        totalStudents: FieldValue.increment(1),
      }).catch(() => {});
    }

    const signInToken = await auth.createCustomToken(uid);
    await db.collection('signInTokens').doc(leadId).set({
      token: signInToken,
      uid: uid,
      isNewUser: isNewUser,
      courseId: lead.courseId || null,
      enrollmentId: enrollmentRef.id,
      used: false,
      createdAt: FieldValue.serverTimestamp(),
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    await dedupeRef.set({
      type: eventType,
      processedAt: FieldValue.serverTimestamp(),
      acted: true,
      enrollmentId: enrollmentRef.id,
    });

    console.log(`COPE ENROLLED: ${lead.email} | course: ${lead.courseId} | newUser: ${isNewUser} | $${paidAmount} (${amountSource})`);

    return res.status(200).json({ ok: true, enrollmentId: enrollmentRef.id });
  } catch (err) {
    console.error('Cope webhook processing error:', err);
    return res.status(500).json({ error: 'Internal processing error: ' + err.message });
  }
};

module.exports.config = {
  api: { bodyParser: false },
};
