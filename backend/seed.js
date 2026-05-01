const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin
const serviceAccount = require(path.join(__dirname, 'firebase-service-account.json'));
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

async function seedData() {
    console.log('🌱 Starting seed process...');
    
    // Find our test user Mike Reynolds
    const usersSnap = await db.collection('users').where('email', '==', 'mike@fixr.test').get();
    
    if (usersSnap.empty) {
        console.error('❌ Could not find Mike Reynolds (mike@fixr.test) in users collection. Run the curl registration test first.');
        process.exit(1);
    }
    
    const contractorUserId = usersSnap.docs[0].id;
    console.log(`Found Mike Reynolds with ID: ${contractorUserId}`);
    
    // ── 1. Create Clients ──
    const clientsData = [
        { name: 'Sarah Jenkins', email: 'sarah@email.com', phone: '(864) 555-1234', address: '142 Hillcrest Dr, Spartanburg, SC 29302', status: 'Active' },
        { name: 'Ellen Rossi', email: 'ellen.r@email.com', phone: '(864) 555-8822', address: '88 Pine St, Spartanburg, SC 29306', status: 'Active' },
        { name: 'Green Valley HOA', email: 'billing@gvhoa.com', phone: '(864) 555-0099', address: '100 Green Valley Pkwy, Moore, SC 29369', status: 'Active' },
        { name: 'Dave Miller', email: 'dmiller88@email.com', phone: '(864) 555-3341', address: '45 Oak Ln, Boiling Springs, SC 29316', status: 'Inactive' }
    ];
    
    const clientIds = {};
    for (const data of clientsData) {
        const ref = await db.collection('clients').add({
            contractor_user_id: contractorUserId,
            ...data,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        clientIds[data.name] = ref.id;
        console.log(`Created client: ${data.name} (${ref.id})`);
    }
    
    // ── 2. Create Jobs ──
    const jobsData = [
        { client_id: clientIds['Sarah Jenkins'], title: 'Leaking Water Heater', stage: 'New', priority: 'Urgent', value: null },
        { client_id: null, title: 'Kitchen Faucet Install (Tom Davis)', stage: 'New', priority: 'Normal', value: null },
        { client_id: clientIds['Ellen Rossi'], title: 'Master Bath Re-pipe', stage: 'Scheduled', priority: 'Normal', value: 1250, due_date: 'Tomorrow, 9am' },
        { client_id: null, title: 'HVAC Annual Tune-up (Marcus Johnson)', stage: 'In Progress', priority: 'Normal', value: 250 },
        { client_id: clientIds['Dave Miller'], title: 'Sump Pump Replacement', stage: 'Completed', priority: 'Normal', value: 800 },
        { client_id: clientIds['Green Valley HOA'], title: 'Gas Line Repair', stage: 'Invoiced', priority: 'High', value: 450 }
    ];
    
    let position = 0;
    for (const data of jobsData) {
        const ref = await db.collection('jobs').add({
            contractor_user_id: contractorUserId,
            ...data,
            position: position++,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log(`Created job: ${data.title} (${ref.id})`);
    }
    
    console.log('✅ Seeding complete!');
    process.exit(0);
}

seedData().catch(err => {
    console.error('Seed error:', err);
    process.exit(1);
});
