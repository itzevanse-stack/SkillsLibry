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

// (config is attached to module.exports further down, after the handler
// is assigned — see bottom of file. Doing it here would be wiped out by
// the reassignment below.)

// Normalizes a pasted private key regardless of how it got mangled:
// - strips surrounding quotes if the whole value got quoted
// - converts literal "\n" text into real newlines
// - trims stray whitespace
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
    // Preferred, foolproof path: one base64-encoded blob of the entire
    // service account JSON file. Immune to newline/quote mangling entirely
    // because it's a single opaque string with no special characters.
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
      const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
      const serviceAccount = JSON.parse(json);
      initializeApp({ credential: cert(serviceAccount) });
      return getFirestore();
    }

    // Fallback: the three separate env vars, with defensive normalization.
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

// Verifies Cope's signature header: "t=<unix_timestamp>,v1=<hex_hmac_sha256>"
// HMAC is computed over "{timestamp}.{rawBody}" using the webhook signing
// secret (shown once when the endpoint is created in the Cope dashboard).
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

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    console.error('Cope webhook: failed to read request body', e);
    return res.status(400).json({ error: 'Could not read request body' });
  }

  // Accept either header name — Cope's test events use X-Webhook-Signature;
  // production events may use X-Cope-Signature. Check both defensively.
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

  // Handle Cope's synthetic test event (no real order data) — just confirm
  // we received and verified it, without touching Firestore.
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

    const enrollmentRef = await db.collection('enrollments').add({
      courseId: lead.courseId,
      courseTitle: lead.courseTitle || '',
      instructorId: lead.instructorId || null,
      uid: lead.uid || null,
      studentEmail: lead.email,
      studentName: lead.name,
      leadId: leadId,
      paymentProcessor: 'cope',
      subscriptionStatus: 'active',
      failedPayments: 0,
      copeEventId: eventId,
      enrolledAt: FieldValue.serverTimestamp(),
    });

    await leadRef.update({ status: 'converted', enrollmentId: enrollmentRef.id, convertedAt: FieldValue.serverTimestamp() });

    if (lead.courseId) {
      await db.collection('courses').doc(lead.courseId).update({
        totalStudents: FieldValue.increment(1),
      }).catch(() => {});
    }

    await dedupeRef.set({
      type: eventType,
      processedAt: FieldValue.serverTimestamp(),
      acted: true,
      enrollmentId: enrollmentRef.id,
    });

    console.log(`COPE ENROLLED: ${lead.email} | course: ${lead.courseId}`);

    return res.status(200).json({ ok: true, enrollmentId: enrollmentRef.id });
  } catch (err) {
    console.error('Cope webhook processing error:', err);
    return res.status(500).json({ error: 'Internal processing error: ' + err.message });
  }
};

// Disable automatic body parsing so we can verify the HMAC against the
// exact raw bytes Cope signed — a parsed/re-stringified body will not
// match the signature. Must be attached AFTER module.exports is assigned
// above, otherwise this gets wiped out by that reassignment.
module.exports.config = {
  api: { bodyParser: false },
};
