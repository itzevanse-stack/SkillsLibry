// api/flutterwave-webhook.js
// Deploy this on Vercel — it lives at /api/flutterwave-webhook

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { Resend } from 'resend';
import crypto from 'crypto';

/* ── Init Firebase Admin (server-side) ── */
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const db     = getFirestore();
const resend = new Resend(process.env.RESEND_API_KEY);

/* ── Flutterwave secret hash ── */
const FLW_SECRET_HASH = process.env.FLW_SECRET_HASH; // set in Vercel env vars

export default async function handler(req, res) {
  /* Only allow POST */
  if (req.method !== 'POST') return res.status(405).end('Method not allowed');

  /* Verify the request is from Flutterwave */
  const signature = req.headers['verif-hash'];
  if (!signature || signature !== FLW_SECRET_HASH) {
    console.error('Invalid Flutterwave signature');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { event, data } = req.body;

  /* Only process successful charges */
  if (event !== 'charge.completed') return res.status(200).json({ received: true });
  if (data.status !== 'successful')  return res.status(200).json({ received: true });

  try {
    /* ── Verify transaction with Flutterwave API ── */
    const verifyRes = await fetch(
      `https://api.flutterwave.com/v3/transactions/${data.id}/verify`,
      {
        headers: {
          Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );
    const verify = await verifyRes.json();

    if (verify.status !== 'success' || verify.data.status !== 'successful') {
      console.error('Transaction verification failed', verify);
      return res.status(200).json({ error: 'Verification failed' });
    }

    const tx           = verify.data;
    const meta         = tx.meta || {};
    const courseId     = meta.courseId;
    const instructorId = meta.instructorId;
    const affiliateCode = meta.affiliateCode || null;
    const plan         = meta.plan || 'full';
    const studentEmail = tx.customer.email;
    const studentName  = tx.customer.name;
    const amount       = tx.amount;
    const currency     = tx.currency;
    const txId         = String(tx.id);

    /* ── Check for duplicate enrollment ── */
    const enrollId = courseId + '_' + tx.customer.email.replace(/[^a-z0-9]/gi,'_');
    const existing = await db.collection('enrollments').doc(enrollId).get();
    if (existing.exists) {
      console.log('Duplicate enrollment ignored:', enrollId);
      return res.status(200).json({ received: true, note: 'duplicate' });
    }

    /* ── Revenue split ── */
    const instructorCut = Math.round(amount * 0.60 * 100) / 100;
    const platformCut   = Math.round(amount * 0.40 * 100) / 100;
    const affiliateCut  = affiliateCode ? Math.round(amount * 0.10 * 100) / 100 : 0;

    /* ── Write enrollment ── */
    await db.collection('enrollments').doc(enrollId).set({
      courseId,
      instructorId,
      studentEmail,
      studentName,
      paidAmount:    amount,
      currency,
      transactionId: txId,
      plan,
      instructorCut,
      platformCut,
      affiliateCut,
      affiliateCode,
      progress: { completedLessons: [], percentComplete: 0 },
      enrolledAt: FieldValue.serverTimestamp(),
    });

    /* ── Update course student count ── */
    await db.collection('courses').doc(courseId).update({
      totalStudents: FieldValue.increment(1),
      totalRevenue:  FieldValue.increment(amount),
    }).catch(() => {}); /* ignore if course doc doesn't exist yet */

    /* ── Update instructor pending payout ── */
    await db.collection('instructorPayouts').doc(instructorId).set({
      pendingAmount: FieldValue.increment(instructorCut),
      currency,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    /* ── Record affiliate commission ── */
    if (affiliateCode && affiliateCut > 0) {
      await db.collection('affiliateEarnings').add({
        affiliateCode,
        courseId,
        commission: affiliateCut,
        currency,
        txId,
        createdAt: FieldValue.serverTimestamp(),
      });
    }

    /* ── Send welcome email via Resend ── */
    await resend.emails.send({
      from: 'SkillsLibry <hello@skillslibry.com>',
      to:   studentEmail,
      subject: '🎉 You\'re enrolled! Let\'s get started',
      html: `
        <div style="font-family:'Inter',sans-serif;max-width:560px;margin:0 auto;padding:40px 24px;">
          <div style="background:linear-gradient(135deg,#4ecca3,#6c63ff);border-radius:12px;padding:32px;text-align:center;margin-bottom:32px;">
            <h1 style="color:#fff;font-size:28px;margin:0 0 8px;font-family:'Poppins',sans-serif;">Welcome aboard, ${studentName}! 🚀</h1>
            <p style="color:rgba(255,255,255,.85);margin:0;font-size:15px;">Your enrollment is confirmed.</p>
          </div>
          <p style="color:#4a4d6a;font-size:15px;line-height:1.7;">
            You now have full access to your course. Your journey to earning with digital skills starts right now.
          </p>
          <div style="background:#f8f9fc;border-radius:10px;padding:20px 24px;margin:24px 0;">
            <p style="margin:0 0 4px;font-size:12px;color:#8b8fa8;font-weight:600;text-transform:uppercase;letter-spacing:.06em;">Transaction details</p>
            <p style="margin:0;font-size:14px;color:#0d0d1a;">Amount: <strong>${currency} ${amount}</strong></p>
            <p style="margin:4px 0 0;font-size:14px;color:#0d0d1a;">Reference: <strong>${txId}</strong></p>
          </div>
          <div style="text-align:center;margin-top:32px;">
            <a href="https://skillslibry.com/player?course=${courseId}"
              style="background:#4ecca3;color:#0d0d1a;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;text-decoration:none;display:inline-block;">
              Start your course →
            </a>
          </div>
          <p style="color:#8b8fa8;font-size:12px;text-align:center;margin-top:32px;">
            SkillsLibry · People with passion to learn &amp; execute can change the world for good.
          </p>
        </div>
      `,
    });

    console.log(`✓ Enrollment complete: ${studentEmail} → course ${courseId} (${currency} ${amount})`);
    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
