// api/flutterwave-webhook.js
import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getFirestore, FieldValue }      from 'firebase-admin/firestore';

if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const db = getFirestore();
const PLATFORM_SUB_NGN      = 10500;
const INSTRUCTOR_SHARE      = 0.60;   // 60% of course fee
const PLATFORM_SHARE        = 0.40;   // 40% of course fee
const SUB_INSTRUCTOR_SHARE  = 0.20;   // 20% of monthly subscription to instructor
const SUB_PLATFORM_SHARE    = 0.80;   // 80% of monthly subscription to platform

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const signature = req.headers['verif-hash'];
  if (!signature || signature !== process.env.FLW_SECRET_HASH)
    return res.status(401).json({ error: 'Unauthorized' });

  const { event, data } = req.body;
  if (event !== 'charge.completed') return res.status(200).json({ received: true });
  if (data.status !== 'successful')  return res.status(200).json({ received: true });

  try {
    const verifyRes = await fetch(
      `https://api.flutterwave.com/v3/transactions/${data.id}/verify`,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );
    const verify = await verifyRes.json();
    if (verify.status !== 'success' || verify.data.status !== 'successful')
      return res.status(200).json({ error: 'Verification failed' });

    const tx           = verify.data;
    const meta         = tx.meta || {};
    const paymentType  = meta.paymentType || 'enrollment';
    const courseId     = meta.courseId;
    const instructorId = meta.instructorId;
    const affiliateCode = meta.affiliateCode || null;
    const studentEmail = tx.customer.email;
    const studentName  = tx.customer.name || '';
    const totalAmount  = tx.amount;
    const currency     = tx.currency;
    const txId         = String(tx.id);

    if (paymentType === 'enrollment') {
      const courseFeeNGN = parseFloat(meta.courseFeeNGN || 0);
      const rate         = courseFeeNGN > 0 ? totalAmount / (courseFeeNGN + PLATFORM_SUB_NGN) : 1;
      const courseFee    = Math.round(courseFeeNGN * rate * 100) / 100;
      const subFee       = Math.round(PLATFORM_SUB_NGN * rate * 100) / 100;
      const instructorCut    = Math.round((courseFee * INSTRUCTOR_SHARE + subFee * SUB_INSTRUCTOR_SHARE) * 100) / 100;
      const platformCut      = Math.round((courseFee * PLATFORM_SHARE  + subFee * SUB_PLATFORM_SHARE)  * 100) / 100;
      const instructorSubCut = Math.round(subFee * SUB_INSTRUCTOR_SHARE * 100) / 100; // ₦2,100 of the ₦10,500
      const affiliateCut  = affiliateCode ? Math.round(courseFee * 0.10 * 100) / 100 : 0;

      const enrollId = courseId + '_' + studentEmail.replace(/[^a-z0-9]/gi, '_');
      const existing = await db.collection('enrollments').doc(enrollId).get();
      if (existing.exists) return res.status(200).json({ received: true, note: 'duplicate' });

      const nextBilling = new Date();
      nextBilling.setDate(nextBilling.getDate() + 30);

      await db.collection('enrollments').doc(enrollId).set({
        courseId, instructorId, studentEmail, studentName,
        paidAmount: totalAmount, courseFee, subFee, currency, transactionId: txId,
        instructorCut, platformCut, affiliateCut, affiliateCode,
        subscriptionStatus: 'active',
        failedPayments:     0,
        nextBillingDate:    nextBilling.toISOString(),
        nextBillingAmount:  subFee,
        progress: { completedLessons: [], percentComplete: 0 },
        enrolledAt: FieldValue.serverTimestamp(),
      });

      await db.collection('courses').doc(courseId).update({
        totalStudents: FieldValue.increment(1),
        totalRevenue:  FieldValue.increment(totalAmount),
      }).catch(() => {});

      await db.collection('instructorPayouts').doc(instructorId).set({
        pendingAmount: FieldValue.increment(instructorCut),
        currency, updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });

      if (affiliateCode && affiliateCut > 0) {
        await db.collection('affiliateEarnings').add({
          affiliateCode, courseId, commission: affiliateCut, currency, txId,
          createdAt: FieldValue.serverTimestamp(),
        });
      }

      console.log(`ENROLLED: ${studentEmail} | Instructor: ${instructorCut} | Platform: ${platformCut}`);

    } else if (paymentType === 'subscription_renewal') {
      const enrollId    = meta.enrollmentId;
      const nextBilling = new Date();
      nextBilling.setDate(nextBilling.getDate() + 30);

      // 80/20 split on renewal: platform gets 80%, instructor gets 20%
      const renewalInstructorCut = Math.round(totalAmount * SUB_INSTRUCTOR_SHARE * 100) / 100;
      const renewalPlatformCut   = Math.round(totalAmount * SUB_PLATFORM_SHARE   * 100) / 100;

      // Get instructorId from enrollment
      const enrollDoc = await db.collection('enrollments').doc(enrollId).get();
      const renewInstructorId = enrollDoc.exists ? enrollDoc.data().instructorId : null;

      await db.collection('enrollments').doc(enrollId).update({
        subscriptionStatus: 'active',
        failedPayments:     0,
        lastRenewalDate:    FieldValue.serverTimestamp(),
        nextBillingDate:    nextBilling.toISOString(),
        lastRenewalTxId:    txId,
      });

      // Credit instructor their 20% cut
      if(renewInstructorId){
        await db.collection('instructorPayouts').doc(renewInstructorId).set({
          pendingAmount: FieldValue.increment(renewalInstructorCut),
          currency, updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }

      await db.collection('platformRevenue').add({
        type: 'subscription_renewal', enrollmentId: enrollId,
        amount: renewalPlatformCut, instructorCut: renewalInstructorCut,
        currency, txId, createdAt: FieldValue.serverTimestamp(),
      });

    } else if (paymentType === 'subscription_failed') {
      const enrollId    = meta.enrollmentId;
      const enrollSnap  = await db.collection('enrollments').doc(enrollId).get();
      if (!enrollSnap.exists) return res.status(200).json({ error: 'Not found' });

      const failCount = (enrollSnap.data().failedPayments || 0) + 1;

      await db.collection('enrollments').doc(enrollId).update({
        subscriptionStatus: failCount >= 2 ? 'revoked' : 'payment_failed',
        failedPayments:     failCount,
        ...(failCount >= 2 ? { revokedAt: FieldValue.serverTimestamp(), revokedReason: 'payment_failed_twice' } : {}),
      });

      console.log(`SUBSCRIPTION ${failCount >= 2 ? 'REVOKED' : 'FAILED'}: ${enrollId} (${failCount}/2)`);
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
