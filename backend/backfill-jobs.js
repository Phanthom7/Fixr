/**
 * One-shot backfill: populate `homeowner_user_id` on existing job docs by
 * looking up their linked lead. Run with `node backend/backfill-jobs.js`.
 * Safe to run repeatedly (idempotent — skips jobs that already have the field).
 */
require('dotenv').config();
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');

const serviceAccountPath = path.join(__dirname, 'firebase-service-account.json');
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else if (fs.existsSync(serviceAccountPath)) {
    serviceAccount = require(serviceAccountPath);
} else {
    console.error('No FIREBASE_SERVICE_ACCOUNT env or backend/firebase-service-account.json found.');
    process.exit(1);
}
if (typeof serviceAccount.private_key === 'string') {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
}

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

(async () => {
    const snap = await db.collection('jobs').get();
    let scanned = 0, patched = 0, skipped = 0, missingLead = 0;

    for (const doc of snap.docs) {
        scanned++;
        const job = doc.data();
        if (job.homeowner_user_id) { skipped++; continue; }
        if (!job.lead_id) { missingLead++; continue; }

        const leadDoc = await db.collection('leads').doc(job.lead_id).get();
        if (!leadDoc.exists) { missingLead++; continue; }
        const homeownerUserId = leadDoc.data().userId || null;
        if (!homeownerUserId) { missingLead++; continue; }

        await doc.ref.update({ homeowner_user_id: homeownerUserId });
        patched++;
        console.log(`  patched job ${doc.id} → homeowner_user_id=${homeownerUserId}`);
    }

    console.log(`\nDone. scanned=${scanned} patched=${patched} already_set=${skipped} no_lead_link=${missingLead}`);
    process.exit(0);
})().catch(err => {
    console.error('Backfill failed:', err);
    process.exit(1);
});
