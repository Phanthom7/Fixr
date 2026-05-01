require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const admin   = require('firebase-admin');
const path    = require('path');

// ── Firebase Init ─────────────────────────────────────────────────────────────
const serviceAccount = require(path.join(__dirname, 'firebase-service-account.json'));
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app  = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../')));

console.log('✅ Firebase Admin connected to project:', serviceAccount.project_id);

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ status: 'OK', db: 'Firestore' }));

// ── REGISTER: HOMEOWNER ───────────────────────────────────────────────────────
app.post('/api/auth/register/homeowner', async (req, res) => {
    const {
        name, email, password, phone,
        service, job_title, description,
        urgency, property_type, home_size, budget_range, zip_code
    } = req.body;

    if (!name || !email || !password || !service) {
        return res.status(400).json({ error: 'Name, email, password, and service are required.' });
    }

    try {
        // Check duplicate email
        const existing = await db.collection('users').where('email', '==', email).get();
        if (!existing.empty) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        const password_hash = await bcrypt.hash(password, 10);
        const userRef = await db.collection('users').add({
            name, email, password_hash,
            role: 'homeowner',
            status: 'active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const leadRef = await db.collection('leads').add({
            userId: userRef.id,
            name, email,
            phone: phone || null,
            service,
            job_title: job_title || null,
            description: description || null,
            urgency: urgency || null,
            property_type: property_type || null,
            home_size: home_size || null,
            budget_range: budget_range || null,
            zip_code: zip_code || null,
            status: 'New',
            assigned_contractor_id: null,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message: 'Account created and request submitted!',
            userId:  userRef.id,
            leadId:  leadRef.id,
            role:    'homeowner',
            name
        });
    } catch (err) {
        console.error('Register homeowner error:', err);
        res.status(500).json({ error: 'Failed to create account.' });
    }
});

// ── REGISTER: CONTRACTOR ──────────────────────────────────────────────────────
app.post('/api/auth/register/contractor', async (req, res) => {
    const { name, email, password, phone, trade, experience_years, plan } = req.body;

    if (!name || !email || !password || !phone || !trade) {
        return res.status(400).json({ error: 'Name, email, password, phone, and trade are required.' });
    }

    const validPlans   = ['Starter', 'Pro', 'Elite'];
    const selectedPlan = validPlans.includes(plan) ? plan : 'Starter';

    try {
        const existing = await db.collection('users').where('email', '==', email).get();
        if (!existing.empty) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        const password_hash = await bcrypt.hash(password, 10);

        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14);

        const userRef = await db.collection('users').add({
            name, email, password_hash,
            role:   'contractor',
            status: 'active',
            subscription: {
                plan:          selectedPlan,
                status:        'trial',
                trial_ends_at: trialEnd.toISOString(),
                billing_date:  null
            },
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const contractorRef = await db.collection('contractors').add({
            userId: userRef.id,
            name, email, phone, trade,
            experience_years: experience_years || null,
            status:    'active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message:      'Account created! Your 14-day free trial has started.',
            userId:       userRef.id,
            contractorId: contractorRef.id,
            plan:         selectedPlan,
            role:         'contractor',
            name
        });
    } catch (err) {
        console.error('Register contractor error:', err);
        res.status(500).json({ error: 'Failed to create account.' });
    }
});

// ── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const snap = await db.collection('users').where('email', '==', email).get();
        if (snap.empty) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const userDoc = snap.docs[0];
        const user    = userDoc.data();

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        res.json({
            message:      'Login successful',
            userId:       userDoc.id,
            role:         user.role,
            name:         user.name,
            status:       user.status,
            subscription: user.subscription || null
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed.' });
    }
});

// ── HOMEOWNER: GET THEIR LEADS ────────────────────────────────────────────────
app.get('/api/homeowner/leads/:userId', async (req, res) => {
    try {
        const snap = await db.collection('leads')
            .where('userId', '==', req.params.userId)
            .orderBy('createdAt', 'desc')
            .get();

        const leads = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(leads);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch your requests.' });
    }
});

// ── MESSAGES: GET FOR A LEAD ──────────────────────────────────────────────────
app.get('/api/messages/:leadId', async (req, res) => {
    try {
        const snap = await db.collection('messages')
            .where('lead_id', '==', req.params.leadId)
            .orderBy('createdAt', 'asc')
            .get();

        const messages = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(messages);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch messages.' });
    }
});

// ── MESSAGES: SEND ────────────────────────────────────────────────────────────
app.post('/api/messages', async (req, res) => {
    const { lead_id, sender_id, receiver_id, body } = req.body;
    if (!lead_id || !sender_id || !receiver_id || !body) {
        return res.status(400).json({ error: 'lead_id, sender_id, receiver_id, and body are required.' });
    }
    try {
        const msgRef = await db.collection('messages').add({
            lead_id, sender_id, receiver_id, body,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ message: 'Message sent', messageId: msgRef.id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to send message.' });
    }
});

// ── LEADS: GET ALL OPEN (contractor browse) ───────────────────────────────────
app.get('/api/leads', async (_req, res) => {
    try {
        const snap = await db.collection('leads')
            .where('status', 'in', ['New', 'Open'])
            .orderBy('createdAt', 'desc')
            .get();

        const leads = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(leads);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch leads.' });
    }
});

// ── LEADS: ACCEPT (contractor claims lead) ────────────────────────────────────
app.post('/api/leads/:id/accept', async (req, res) => {
    const { contractor_user_id } = req.body;
    if (!contractor_user_id) return res.status(400).json({ error: 'contractor_user_id is required.' });

    try {
        const leadRef = db.collection('leads').doc(req.params.id);
        const leadDoc = await leadRef.get();
        
        if (!leadDoc.exists) return res.status(404).json({ error: 'Lead not found.' });
        if (leadDoc.data().status !== 'New' && leadDoc.data().status !== 'Open') {
            return res.status(400).json({ error: 'Lead is no longer available.' });
        }

        const leadData = leadDoc.data();

        // 1. Update lead
        await leadRef.update({
            status: 'Matched',
            assigned_contractor_id: contractor_user_id
        });

        // 2. Check if client exists for this contractor, if not create one
        let clientId = null;
        if (leadData.email) {
            const clientSnap = await db.collection('clients')
                .where('contractor_user_id', '==', contractor_user_id)
                .where('email', '==', leadData.email)
                .get();
            
            if (!clientSnap.empty) {
                clientId = clientSnap.docs[0].id;
            }
        }

        if (!clientId) {
            const clientRef = await db.collection('clients').add({
                contractor_user_id,
                name: leadData.name,
                email: leadData.email || null,
                phone: leadData.phone || null,
                address: leadData.zip_code || null,
                notes: 'From Lead',
                status: 'Active',
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
            clientId = clientRef.id;
        }

        // 3. Create Job
        const jobRef = await db.collection('jobs').add({
            contractor_user_id,
            client_id: clientId,
            title: leadData.job_title || leadData.service,
            description: leadData.description || null,
            stage: 'New',
            value: null,
            due_date: null,
            trade: leadData.service,
            priority: leadData.urgency === 'ASAP' ? 'Urgent' : 'Normal',
            position: 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Lead accepted!', jobId: jobRef.id, clientId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to accept lead.' });
    }
});

// ── CLIENTS: LIST ─────────────────────────────────────────────────────────────
app.get('/api/clients', async (req, res) => {
    const { contractor_id } = req.query;
    if (!contractor_id) return res.status(400).json({ error: 'contractor_id is required.' });
    try {
        const snap = await db.collection('clients')
            .where('contractor_user_id', '==', contractor_id)
            .orderBy('createdAt', 'desc')
            .get();

        const clients = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(clients);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch clients.' });
    }
});

// ── CLIENTS: CREATE ───────────────────────────────────────────────────────────
app.post('/api/clients', async (req, res) => {
    const { contractor_user_id, name, email, phone, address, notes, status } = req.body;
    if (!contractor_user_id || !name) {
        return res.status(400).json({ error: 'contractor_user_id and name are required.' });
    }
    try {
        const ref = await db.collection('clients').add({
            contractor_user_id, name,
            email:   email   || null,
            phone:   phone   || null,
            address: address || null,
            notes:   notes   || null,
            status:  status  || 'Active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ message: 'Client created', clientId: ref.id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create client.' });
    }
});

// ── CLIENTS: UPDATE ───────────────────────────────────────────────────────────
app.put('/api/clients/:id', async (req, res) => {
    const { name, email, phone, address, notes, status, contractor_user_id } = req.body;
    try {
        const ref = db.collection('clients').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists || doc.data().contractor_user_id !== contractor_user_id) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        await ref.update({ name, email: email||null, phone: phone||null, address: address||null, notes: notes||null, status: status||'Active' });
        res.json({ message: 'Client updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update client.' });
    }
});

// ── CLIENTS: DELETE ───────────────────────────────────────────────────────────
app.delete('/api/clients/:id', async (req, res) => {
    const { contractor_user_id } = req.body;
    try {
        const ref = db.collection('clients').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists || doc.data().contractor_user_id !== contractor_user_id) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        await ref.delete();
        res.json({ message: 'Client deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete client.' });
    }
});

// ── JOBS: LIST ────────────────────────────────────────────────────────────────
app.get('/api/jobs', async (req, res) => {
    const { contractor_id } = req.query;
    if (!contractor_id) return res.status(400).json({ error: 'contractor_id is required.' });
    try {
        const snap = await db.collection('jobs')
            .where('contractor_user_id', '==', contractor_id)
            .orderBy('position', 'asc')
            .get();

        const jobs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(jobs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch jobs.' });
    }
});

// ── JOBS: CREATE ──────────────────────────────────────────────────────────────
app.post('/api/jobs', async (req, res) => {
    const { contractor_user_id, client_id, title, description, stage, value, due_date, trade, priority } = req.body;
    if (!contractor_user_id || !title) {
        return res.status(400).json({ error: 'contractor_user_id and title are required.' });
    }
    try {
        const ref = await db.collection('jobs').add({
            contractor_user_id,
            client_id:   client_id   || null,
            title,
            description: description || null,
            stage:       stage       || 'New',
            value:       value       || null,
            due_date:    due_date    || null,
            trade:       trade       || null,
            priority:    priority    || 'Normal',
            position:    0,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ message: 'Job created', jobId: ref.id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create job.' });
    }
});

// ── JOBS: UPDATE ──────────────────────────────────────────────────────────────
app.put('/api/jobs/:id', async (req, res) => {
    const { contractor_user_id, title, description, stage, value, due_date, trade, priority, client_id, position } = req.body;
    try {
        const ref = db.collection('jobs').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists || doc.data().contractor_user_id !== contractor_user_id) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        await ref.update({
            title, description: description||null, stage: stage||'New',
            value: value||null, due_date: due_date||null, trade: trade||null,
            priority: priority||'Normal', client_id: client_id||null,
            position: position||0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ message: 'Job updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update job.' });
    }
});

// ── JOBS: STAGE UPDATE (kanban drag) ─────────────────────────────────────────
app.patch('/api/jobs/:id/stage', async (req, res) => {
    const { stage, position } = req.body;
    const validStages = ['New', 'Scheduled', 'In Progress', 'Completed', 'Invoiced'];
    if (!validStages.includes(stage)) {
        return res.status(400).json({ error: 'Invalid stage.' });
    }
    try {
        await db.collection('jobs').doc(req.params.id).update({
            stage,
            position: position || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ message: 'Stage updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update stage.' });
    }
});

// ── JOBS: DELETE ──────────────────────────────────────────────────────────────
app.delete('/api/jobs/:id', async (req, res) => {
    const { contractor_user_id } = req.body;
    try {
        const ref = db.collection('jobs').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists || doc.data().contractor_user_id !== contractor_user_id) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        await ref.delete();
        res.json({ message: 'Job deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete job.' });
    }
});

// ── INVOICES: LIST ────────────────────────────────────────────────────────────
app.get('/api/invoices', async (req, res) => {
    const { contractor_id } = req.query;
    if (!contractor_id) return res.status(400).json({ error: 'contractor_id is required.' });
    try {
        const snap = await db.collection('invoices')
            .where('contractor_user_id', '==', contractor_id)
            .orderBy('createdAt', 'desc')
            .get();

        const invoices = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(invoices);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch invoices.' });
    }
});

// ── SUBSCRIPTIONS: GET ────────────────────────────────────────────────────────
app.get('/api/subscriptions/:userId', async (req, res) => {
    try {
        const doc = await db.collection('users').doc(req.params.userId).get();
        if (!doc.exists) return res.status(404).json({ error: 'User not found.' });
        res.json(doc.data().subscription || {});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch subscription.' });
    }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
