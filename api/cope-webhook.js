// api/cope-webhook.js
//
// Receives Cope's signed webhook events (CloudEvents 1.0 format) and grants
// course access the moment a payment actually completes. This is the ONLY
// authoritative source of enrollment for external-checkout courses — the
// /welcome redirect page is purely cosmetic, per Cope's own docs.
//
// Docs referenced: https://docs.cope.com/webhooks/signing
//                   https://docs.cope.com/quickstart/build-an-integration
//
// ⚠️ ONE THING TO VERIFY before going live: the exact field name Cope uses
// to carry the `client_reference_id` we attach to the checkout link. This
// handler checks several likely locations defensively — once you have
// dashboard access, trigger a synthetic test event and confirm which path
// actually holds it, then trim the others.

import crypto from 'crypto';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

// Vercel: disable automatic body parsing so we can verify the HMAC against
// the exact raw bytes Cope signed — a parsed/re-stringified body will not
// match the signature.
export const config = {
  api: { bodyParser: false },
};

function getFirebaseAdmin() {
  if (!getApps().length) {
    initializeApp({
      credential: cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
      }),
    });
  }
  return getFirestore();
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

// Verifies Cope's signature header: "t=<unix_timestamp>,v1=<hex_hmac_sha256>"
// HMAC is computed over "{timestamp}.{rawBody}" using the webhook signing
// secret (shown once when the endpoint is created in the Cope dashboard).
function verifyCopeSignature(rawBody, signatureHeader, signingSecret) {
  if (!signatureHeader) return { ok: false, reason: 'Missing X-Cope-Signature header' };

  const parts = Object.fromEntries(
    signatureHeader.split(',').map((p) => p.split('='))
  );
  const timestamp = parts.t;
  const providedSig = parts.v1;

  if (!timestamp || !providedSig) {
    return { ok: false, reason: 'Malformed X-Cope-Signature header' };
  }

  // Reject anything older than 5 minutes — replay protection, per Cope's docs
  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (ageSeconds > 300) {
    return { ok: false, reason: 'Signature timestamp too old' };
  }

  const expectedSig = crypto
    .createHmac('sha256', signingSecret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');

  const sigMatches =
    expectedSig.length === providedSig.length &&
    crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(providedSig));

  if (!sigMatches) return { ok: false, reason: 'Signature mismatch' };
  return { ok: true };
}

// Pulls the client_reference_id (our leadId) out of the CloudEvents payload,
// checking a few plausible locations until we confirm the exact one.
function extractLeadId(event) {
  const data = event.data || {};
  return (
    data.client_reference_id ||
    (data.cart && data.cart.client_reference_id) ||
    (data.order && data.order.client_reference_id) ||
    (data.checkout && data.checkout.client_reference_id) ||
    data.metadata?.client_reference_id ||
    null
  );
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const rawBody = await readRawBody(req);
  const signingSecret = process.env.COPE_WEBHOOK_SIGNING_SECRET;

  if (!signingSecret) {
    console.error('COPE_WEBHOOK_SIGNING_SECRET is not set in environment variables.');
    return res.status(500).json({ error: 'Server misconfigured: missing webhook signing secret.' });
  }

  const verification = verifyCopeSignature(
    rawBody,
    req.headers['x-cope-signature'],
    signingSecret
  );

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

  const eventId = req.headers['x-cope-event-id'] || event.id;
  const eventType = event.type; // e.g. "cope.cart.order.completed" or "cope.payment.sale.succeeded"

  const db = getFirebaseAdmin();

  try {
    // Dedupe: delivery is at-least-once, so the same event can arrive more
    // than once on retry. Skip anything we've already processed.
    const dedupeRef = db.collection('processedWebhookEvents').doc(eventId);
    const alreadyProcessed = await dedupeRef.get();
    if (alreadyProcessed.exists) {
      return res.status(200).json({ ok: true, note: 'Already processed, skipped.' });
    }

    const isPaymentSuccess =
      eventType &&
      (eventType.includes('order.completed') || eventType.includes('payment.sale.succeeded'));

    if (!isPaymentSuccess) {
      // Not an event we act on (refunds, disputes, cart events, etc.) —
      // acknowledge so Cope doesn't retry, but do nothing further.
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false });
      return res.status(200).json({ ok: true, note: 'Event type not actioned.' });
    }

    const leadId = extractLeadId(event);
    if (!leadId) {
      console.error('Cope webhook: could not find client_reference_id in payload', JSON.stringify(event.data));
      await dedupeRef.set({ type: eventType, processedAt: FieldValue.serverTimestamp(), acted: false, error: 'no leadId found' });
      // Still 200 — this is our bug to fix, not something Cope should retry forever
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

    // Create the real enrollment — same shape as the Flutterwave-driven
    // enrollments, so the rest of the platform (dashboard, community
    // auto-join, player access checks) doesn't need to know which
    // processor was used.
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

    if (lead.instructorId) {
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
    // 5xx tells Cope to retry — appropriate for a transient failure like a
    // Firestore hiccup. Once we've dedup-marked or a genuine data problem
    // occurs, we already returned 200 above rather than reaching here.
    return res.status(500).json({ error: 'Internal processing error' });
  }
}
