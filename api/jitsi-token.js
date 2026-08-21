// api/jitsi-token.js
//
// Mints a short-lived, signed JWT that authorizes one person to join one
// specific live session via 8x8 JaaS. This is the ONLY place moderator
// status is decided — never trust a client-supplied "isModerator" flag,
// since any student could just set that themselves in the browser.
//
// Flow:
//   1. Verify the caller's Firebase ID token (proves who they really are).
//   2. Look up the liveSessions/{sessionId} doc.
//   3. instructorId === caller uid  -> moderator.
//   4. Otherwise, caller must have a real enrollment in that course
//      (checked against Firestore, not trusted from the client) -> regular
//      participant. No enrollment -> 403, no token issued.
//   5. Sign a JaaS-format JWT with the private key (RS256), scoped to this
//      one room, expiring in 90 minutes.
//
// Written in CommonJS to match this project's existing Vercel functions.

const crypto = require('crypto');
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

function getFirebaseAdmin() {
  if (!getApps().length) {
    const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
    const serviceAccount = JSON.parse(json);
    initializeApp({ credential: cert(serviceAccount) });
  }
  return getFirestore();
}

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Minimal hand-rolled RS256 JWT signer — avoids adding a new npm
// dependency just for this one call. Node's built-in crypto module does
// all the actual signing work.
function signJaasToken({ appId, kid, privateKeyPem, roomName, userName, userEmail, userAvatar, isModerator }) {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: 'jitsi',
    iss: 'chat',
    sub: appId,
    room: '*',
    exp: now + 90 * 60,
    nbf: now - 10,
    context: {
      user: {
        name: userName || 'Guest',
        email: userEmail || '',
        moderator: !!isModerator,
        avatar: userAvatar || '',
        'hidden-from-recorder': false,
      },
      features: {
        livestreaming: false,
        recording: false,
        transcription: false,
        'outbound-call': false,
      },
    },
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = encodedHeader + '.' + encodedPayload;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKeyPem)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return signingInput + '.' + signature;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const authHeader = req.headers['authorization'] || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!idToken) return res.status(401).json({ error: 'Missing auth token' });

  let sessionId;
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    sessionId = body && body.sessionId;
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  if (!sessionId) return res.status(400).json({ error: 'Missing sessionId' });

  let db, auth, decoded;
  try {
    db = getFirebaseAdmin();
    auth = getAuth();
    decoded = await auth.verifyIdToken(idToken);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired auth token' });
  }
  const uid = decoded.uid;

  try {
    const sessionSnap = await db.collection('liveSessions').doc(sessionId).get();
    if (!sessionSnap.exists) return res.status(404).json({ error: 'Session not found' });
    const session = sessionSnap.data();

    const isModerator = session.instructorId === uid;

    if (!isModerator) {
      // Must have a real enrollment in this course to join as a participant.
      const enrollSnap = await db.collection('enrollments')
        .where('courseId', '==', session.courseId)
        .get();
      const isEnrolled = enrollSnap.docs.some(function (d) {
        const e = d.data();
        return e.uid === uid || e.studentId === uid;
      });
      if (!isEnrolled) return res.status(403).json({ error: 'Not enrolled in this course' });
    }

    const userSnap = await db.collection('users').doc(uid).get();
    const userData = userSnap.exists ? userSnap.data() : {};

    // Never embed a raw base64 data URI into the JWT as an "avatar" — some
    // photo uploads on this platform store the image inline as
    // data:image/...;base64,... rather than a hosted URL, and stuffing
    // that into a JWT balloons it to tens of thousands of characters,
    // which gets silently rejected/reset by the server. Only pass a real
    // http(s) URL; otherwise leave it blank.
    const rawPhoto = userData.photoURL || '';
    const safeAvatar = /^https?:\/\//i.test(rawPhoto) ? rawPhoto : '';

    const appId = process.env.JAAS_APP_ID;
    const kid = process.env.JAAS_KID;
    const privateKeyPem = Buffer.from(process.env.JAAS_PRIVATE_KEY_BASE64 || '', 'base64').toString('utf8');
    if (!appId || !kid || !privateKeyPem) {
      return res.status(500).json({ error: 'Server misconfigured: missing JaaS credentials' });
    }

    const fullRoomName = appId + '/' + session.roomName;

    const jwt = signJaasToken({
      appId,
      kid,
      privateKeyPem,
      roomName: fullRoomName,
      userName: userData.name || decoded.name || 'Guest',
      userEmail: userData.email || decoded.email || '',
      userAvatar: safeAvatar,
      isModerator,
    });

    return res.status(200).json({
      jwt,
      appId,
      roomName: fullRoomName,
      isModerator,
    });
  } catch (err) {
    console.error('jitsi-token error:', err);
    return res.status(500).json({ error: 'Internal error: ' + err.message });
  }
};
