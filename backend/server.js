require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const admin   = require('firebase-admin');
const path    = require('path');
const fs      = require('fs');
const rateLimit = require('express-rate-limit');

const jwt = require('jsonwebtoken');

// ── Firebase Init ─────────────────────────────────────────────────────────────
const parseFirebaseServiceAccount = (raw) => {
    try {
        return JSON.parse(raw);
    } catch (err) {
        const normalized = raw.replace(
            /("private_key"\s*:\s*")([\s\S]*?)(")/,
            (_match, prefix, key, suffix) => prefix + key.replace(/\r?\n/g, '\\n') + suffix
        );

        return JSON.parse(normalized);
    }
};

const loadFirebaseServiceAccount = () => {
    const localServiceAccountPath = path.join(__dirname, 'firebase-service-account.json');
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;

    if (raw) {
        try {
            return parseFirebaseServiceAccount(raw);
        } catch (err) {
            if (!fs.existsSync(localServiceAccountPath)) {
                throw err;
            }

            console.warn('WARN: FIREBASE_SERVICE_ACCOUNT is invalid; using backend/firebase-service-account.json instead.');
        }
    }

    if (fs.existsSync(localServiceAccountPath)) {
        return require(localServiceAccountPath);
    }

    throw new Error('Set FIREBASE_SERVICE_ACCOUNT or add backend/firebase-service-account.json');
};

let serviceAccount;
try {
    serviceAccount = loadFirebaseServiceAccount();
    if (typeof serviceAccount.private_key === 'string') {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }
} catch (err) {
    console.error('FATAL: Failed to parse FIREBASE_SERVICE_ACCOUNT:', err.message);
    process.exit(1);
}
 
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
 

const db = admin.firestore();

const app  = express();
const port = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
    console.error('FATAL: JWT_SECRET environment variable is not set.');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please try again in 15 minutes.' }
});

app.use(cors());
app.use(express.json());
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Malformed JSON' });
    }
    next();
});

// Serve static frontend files
const frontendRoot = path.join(__dirname, '../');
app.use(express.static(frontendRoot));

console.log('✅ Firebase Admin connected to project:', serviceAccount.project_id);

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ status: 'OK', db: 'Firestore' }));

// ── REGISTER: HOMEOWNER ───────────────────────────────────────────────────────
app.post('/api/auth/register/homeowner', authLimiter, async (req, res) => {
    const {
        name, email, password, phone,
        service, job_title, description,
        urgency, property_type, home_size, budget_range, zip_code, photo_data
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
            photo_data: photo_data || null,
            status: 'New',
            assigned_contractor_id: null,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const token = jwt.sign({ userId: userRef.id, role: 'homeowner' }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'Account created and request submitted!',
            userId:  userRef.id,
            leadId:  leadRef.id,
            role:    'homeowner',
            name,
            token
        });
    } catch (err) {
        console.error('Register homeowner error:', err);
        res.status(500).json({ error: 'Failed to create account.' });
    }
});

// ── REGISTER: CONTRACTOR ──────────────────────────────────────────────────────
app.post('/api/auth/register/contractor', authLimiter, async (req, res) => {
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

        const token = jwt.sign({ userId: userRef.id, role: 'contractor' }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message:      'Account created! Your 14-day free trial has started.',
            userId:       userRef.id,
            contractorId: contractorRef.id,
            plan:         selectedPlan,
            role:         'contractor',
            name,
            token
        });
    } catch (err) {
        console.error('Register contractor error:', err);
        res.status(500).json({ error: 'Failed to create account.' });
    }
});

// ── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, async (req, res) => {
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

        const token = jwt.sign({ userId: userDoc.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message:      'Login successful',
            userId:       userDoc.id,
            role:         user.role,
            name:         user.name,
            status:       user.status,
            subscription: user.subscription || null,
            token
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed.' });
    }
});

// ── HOMEOWNER: GET THEIR LEADS ────────────────────────────────────────────────
app.get('/api/homeowner/leads/:userId', requireAuth, async (req, res) => {
    if (req.user.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    try {
        const snap = await db.collection('leads')
            .where('userId', '==', req.params.userId)
            .get();

        const leads = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        leads.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
        res.json(leads);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch your requests.' });
    }
});

// Resolve the parties on a lead from the perspective of `userId`.
// Returns { lead, leadId, counterpartId } or throws { status, message }.
async function resolveLeadParties(leadId, userId) {
    const leadDoc = await db.collection('leads').doc(leadId).get();
    if (!leadDoc.exists) throw { status: 404, message: 'Lead not found.' };
    const lead = leadDoc.data();

    const homeownerId = lead.userId || null;
    const contractorId = lead.assigned_contractor_id || null;

    let counterpartId = null;
    if (userId === homeownerId) counterpartId = contractorId;
    else if (userId === contractorId) counterpartId = homeownerId;
    else throw { status: 403, message: 'You are not a party to this conversation.' };

    return { lead, leadId, homeownerId, contractorId, counterpartId };
}

// ── MESSAGES: GET FOR A LEAD ──────────────────────────────────────────────────
app.get('/api/messages/:leadId', requireAuth, async (req, res) => {
    try {
        await resolveLeadParties(req.params.leadId, req.user.userId);

        const snap = await db.collection('messages')
            .where('lead_id', '==', req.params.leadId)
            .get();

        const messages = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        messages.sort((a, b) => (a.createdAt?.toMillis?.() || 0) - (b.createdAt?.toMillis?.() || 0));
        res.json(messages);
    } catch (err) {
        if (err.status) return res.status(err.status).json({ error: err.message });
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch messages.' });
    }
});

// ── MESSAGES: SEND ────────────────────────────────────────────────────────────
app.post('/api/messages', requireAuth, async (req, res) => {
    const { lead_id, body } = req.body;
    if (!lead_id || !body || !String(body).trim()) {
        return res.status(400).json({ error: 'lead_id and body are required.' });
    }
    try {
        const { counterpartId } = await resolveLeadParties(lead_id, req.user.userId);
        if (!counterpartId) {
            const role = req.user.role === 'contractor' ? 'homeowner' : 'contractor';
            return res.status(409).json({ error: `No ${role} on the other side of this conversation yet.` });
        }
        const msgRef = await db.collection('messages').add({
            lead_id,
            sender_id: req.user.userId,
            receiver_id: counterpartId,
            body: String(body).trim(),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ message: 'Message sent', messageId: msgRef.id });
    } catch (err) {
        if (err.status) return res.status(err.status).json({ error: err.message });
        console.error(err);
        res.status(500).json({ error: 'Failed to send message.' });
    }
});

async function postSystemMessage(leadId, body) {
    return db.collection('messages').add({
        lead_id: leadId,
        sender_id: 'system',
        receiver_id: null,
        body,
        is_system: true,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

async function getContractorName(contractorUserId) {
    const userDoc = await db.collection('users').doc(contractorUserId).get();
    if (userDoc.exists && userDoc.data().name) return userDoc.data().name;

    const contractorSnap = await db.collection('contractors')
        .where('userId', '==', contractorUserId)
        .limit(1)
        .get();
    if (!contractorSnap.empty) return contractorSnap.docs[0].data().name || null;

    return null;
}

async function createClientAndJobFromLead(leadId, leadData, contractorUserId, quoteData = null) {
    let clientId = null;
    if (leadData.email) {
        const clientSnap = await db.collection('clients')
            .where('contractor_user_id', '==', contractorUserId)
            .where('email', '==', leadData.email)
            .get();

        if (!clientSnap.empty) {
            clientId = clientSnap.docs[0].id;
        }
    }

    if (!clientId) {
        const clientRef = await db.collection('clients').add({
            contractor_user_id: contractorUserId,
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

    const jobRef = await db.collection('jobs').add({
        contractor_user_id: contractorUserId,
        client_id: clientId,
        lead_id: leadId,
        homeowner_user_id: leadData.userId || null,
        quote_id: quoteData?.id || null,
        title: leadData.job_title || leadData.service,
        description: leadData.description || null,
        stage: 'New',
        value: quoteData?.total || null,
        due_date: null,
        trade: leadData.service,
        priority: leadData.urgency === 'ASAP' ? 'Urgent' : 'Normal',
        position: 0,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { clientId, jobId: jobRef.id };
}

// ── LEADS: GET ALL OPEN (contractor browse) ───────────────────────────────────
app.get('/api/leads', requireAuth, async (req, res) => {
    if (req.user.role !== 'contractor') return res.status(403).json({ error: 'Forbidden' });
    try {
        const snap = await db.collection('leads')
            .where('status', 'in', ['New', 'Open'])
            .get();

        const leads = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        leads.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
        res.json(leads);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch leads.' });
    }
});

// ── LEADS: ACCEPT (contractor claims lead) ────────────────────────────────────
app.post('/api/leads/:id/accept', requireAuth, async (req, res) => {
    const contractor_user_id = req.user.userId;
    if (req.user.role !== 'contractor') return res.status(403).json({ error: 'Forbidden' });

    try {
        const contractorName = await getContractorName(contractor_user_id);
        const leadRef = db.collection('leads').doc(req.params.id);
        const result = await db.runTransaction(async (transaction) => {
            const leadDoc = await transaction.get(leadRef);
            if (!leadDoc.exists) {
                throw { status: 404, message: 'Lead not found.' };
            }
            const leadData = leadDoc.data();
            if (leadData.status !== 'New' && leadData.status !== 'Open') {
                throw { status: 400, message: 'Lead is no longer available.' };
            }

            transaction.update(leadRef, {
                status: 'Matched',
                assigned_contractor_id: contractor_user_id,
                contractor_name: contractorName
            });

            return leadData;
        });

        const { clientId, jobId } = await createClientAndJobFromLead(req.params.id, result, contractor_user_id);
        res.json({ message: 'Lead accepted!', jobId, clientId });
    } catch (err) {
        if (err.status) {
            return res.status(err.status).json({ error: err.message });
        }
        console.error(err);
        res.status(500).json({ error: 'Failed to accept lead.' });
    }
});

// ── QUOTES: CONTRACTOR LIST ──────────────────────────────────────────────────
app.get('/api/quotes', requireAuth, async (req, res) => {
    if (req.user.role !== 'contractor') return res.status(403).json({ error: 'Forbidden' });
    try {
        const snap = await db.collection('quotes')
            .where('contractor_user_id', '==', req.user.userId)
            .get();

        const quotes = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        quotes.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
        res.json(quotes);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch quotes.' });
    }
});

// ── QUOTES: HOMEOWNER LIST ───────────────────────────────────────────────────
app.get('/api/homeowner/quotes/:userId', requireAuth, async (req, res) => {
    if (req.user.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    try {
        const snap = await db.collection('quotes')
            .where('homeowner_user_id', '==', req.params.userId)
            .get();

        const quotes = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        quotes.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
        res.json(quotes);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch quotes.' });
    }
});

// ── QUOTES: SEND ─────────────────────────────────────────────────────────────
app.post('/api/quotes', requireAuth, async (req, res) => {
    if (req.user.role !== 'contractor') return res.status(403).json({ error: 'Forbidden' });
    const { lead_id, line_items, notes, valid_until } = req.body;
    if (!lead_id || !Array.isArray(line_items) || line_items.length === 0) {
        return res.status(400).json({ error: 'lead_id and at least one line item are required.' });
    }

    const items = line_items.map(item => {
        const description = String(item.description || '').trim();
        const quantity = Number(item.quantity);
        const unit_price = Number(item.unit_price);
        if (!description || !Number.isFinite(quantity) || quantity <= 0 || !Number.isFinite(unit_price) || unit_price < 0) {
            return null;
        }
        return {
            description,
            quantity,
            unit_price,
            total: Math.round(quantity * unit_price * 100) / 100
        };
    });

    if (items.some(item => item == null)) {
        return res.status(400).json({ error: 'Each line item needs a description, positive quantity, and valid price.' });
    }

    try {
        const leadRef = db.collection('leads').doc(lead_id);
        const leadDoc = await leadRef.get();
        if (!leadDoc.exists) return res.status(404).json({ error: 'Lead not found.' });

        const lead = leadDoc.data();
        if (!['New', 'Open', 'Quoted'].includes(lead.status)) {
            return res.status(400).json({ error: 'Lead is no longer available for quoting.' });
        }
        if (lead.status === 'Quoted' && lead.assigned_contractor_id !== req.user.userId) {
            return res.status(400).json({ error: 'Lead already has a quote from another contractor.' });
        }

        const contractorName = await getContractorName(req.user.userId);
        const total = Math.round(items.reduce((sum, item) => sum + item.total, 0) * 100) / 100;
        const quoteRef = await db.collection('quotes').add({
            contractor_user_id: req.user.userId,
            contractor_name: contractorName,
            homeowner_user_id: lead.userId,
            lead_id,
            customer_name: lead.name || null,
            customer_email: lead.email || null,
            customer_phone: lead.phone || null,
            project_title: lead.job_title || lead.service,
            service: lead.service,
            line_items: items,
            subtotal: total,
            total,
            notes: notes || null,
            valid_until: valid_until || null,
            status: 'Sent',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await leadRef.update({
            status: 'Quoted',
            assigned_contractor_id: req.user.userId,
            contractor_name: contractorName,
            latest_quote_id: quoteRef.id,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({ message: 'Quote sent', quoteId: quoteRef.id, total });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to send quote.' });
    }
});

// ── QUOTES: HOMEOWNER ACCEPT ─────────────────────────────────────────────────
app.post('/api/quotes/:id/accept', requireAuth, async (req, res) => {
    if (req.user.role !== 'homeowner') return res.status(403).json({ error: 'Forbidden' });
    try {
        const quoteRef = db.collection('quotes').doc(req.params.id);
        const quoteDoc = await quoteRef.get();
        if (!quoteDoc.exists) return res.status(404).json({ error: 'Quote not found.' });

        const quote = quoteDoc.data();
        if (quote.homeowner_user_id !== req.user.userId) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        if (quote.status !== 'Sent') {
            return res.status(400).json({ error: 'Quote has already been handled.' });
        }

        const leadRef = db.collection('leads').doc(quote.lead_id);
        const leadDoc = await leadRef.get();
        if (!leadDoc.exists) return res.status(404).json({ error: 'Lead not found.' });
        const lead = leadDoc.data();

        const { clientId, jobId } = await createClientAndJobFromLead(quote.lead_id, lead, quote.contractor_user_id, {
            id: quoteDoc.id,
            total: quote.total
        });

        await quoteRef.update({
            status: 'Accepted',
            acceptedAt: admin.firestore.FieldValue.serverTimestamp(),
            job_id: jobId,
            client_id: clientId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await leadRef.update({
            status: 'Matched',
            accepted_quote_id: quoteDoc.id,
            assigned_contractor_id: quote.contractor_user_id,
            contractor_name: quote.contractor_name || null,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Quote accepted', jobId, clientId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to accept quote.' });
    }
});

// ── CONTRACTOR CONVERSATIONS ──────────────────────────────────────────────────
// Every lead the authenticated contractor has touched: assigned to them OR they
// have authored a quote on. Returned with last-message preview + unread count.
app.get('/api/contractor/conversations', requireAuth, async (req, res) => {
    if (req.user.role !== 'contractor') return res.status(403).json({ error: 'Forbidden' });
    const me = req.user.userId;
    try {
        const [assignedSnap, quotedSnap] = await Promise.all([
            db.collection('leads').where('assigned_contractor_id', '==', me).get(),
            db.collection('quotes').where('contractor_user_id', '==', me).get()
        ]);

        const leadIds = new Set();
        assignedSnap.docs.forEach(d => leadIds.add(d.id));
        quotedSnap.docs.forEach(d => {
            const lid = d.data().lead_id;
            if (lid) leadIds.add(lid);
        });
        if (leadIds.size === 0) return res.json([]);

        const leadDocs = await Promise.all(
            [...leadIds].map(id => db.collection('leads').doc(id).get())
        );

        const conversations = await Promise.all(leadDocs
            .filter(doc => doc.exists)
            .map(async (doc) => {
                const lead = doc.data();
                const msgsSnap = await db.collection('messages')
                    .where('lead_id', '==', doc.id)
                    .get();
                const msgs = msgsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
                msgs.sort((a, b) => (a.createdAt?.toMillis?.() || 0) - (b.createdAt?.toMillis?.() || 0));
                const last = msgs[msgs.length - 1] || null;
                const unread = msgs.filter(m => m.receiver_id === me && !m.read_at).length;

                return {
                    lead_id: doc.id,
                    homeowner_user_id: lead.userId || null,
                    customer_name: lead.name || null,
                    customer_email: lead.email || null,
                    project_title: lead.job_title || lead.service || 'Project',
                    service: lead.service || null,
                    status: lead.status || 'New',
                    is_active_job: ['Matched', 'Scheduled', 'In Progress', 'Complete', 'Completed'].includes(lead.status),
                    last_message: last ? {
                        body: last.is_system ? null : last.body,
                        preview: last.is_system ? '· system update ·' : last.body,
                        sent_by_me: String(last.sender_id) === String(me),
                        is_system: !!last.is_system,
                        createdAt: last.createdAt || null
                    } : null,
                    unread_count: unread,
                    updatedAt: last?.createdAt || lead.updatedAt || lead.createdAt || null
                };
            }));

        conversations.sort((a, b) => {
            const at = a.updatedAt?.toMillis?.() || 0;
            const bt = b.updatedAt?.toMillis?.() || 0;
            return bt - at;
        });
        res.json(conversations);
    } catch (err) {
        console.error('contractor conversations error:', err);
        res.status(500).json({ error: 'Failed to fetch conversations.' });
    }
});

// ── CLIENTS: LIST ─────────────────────────────────────────────────────────────
app.get('/api/clients', requireAuth, async (req, res) => {
    const contractor_id = req.user.userId;
    try {
        const snap = await db.collection('clients')
            .where('contractor_user_id', '==', contractor_id)
            .get();

        const clients = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        clients.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
        res.json(clients);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch clients.' });
    }
});

// ── CLIENTS: CREATE ───────────────────────────────────────────────────────────
app.post('/api/clients', requireAuth, async (req, res) => {
    const { name, email, phone, address, notes, status } = req.body;
    const contractor_user_id = req.user.userId;
    if (!name) {
        return res.status(400).json({ error: 'name is required.' });
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
app.put('/api/clients/:id', requireAuth, async (req, res) => {
    const { name, email, phone, address, notes, status } = req.body;
    const contractor_user_id = req.user.userId;
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
app.delete('/api/clients/:id', requireAuth, async (req, res) => {
    const contractor_user_id = req.user.userId;
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
app.get('/api/jobs', requireAuth, async (req, res) => {
    const contractor_id = req.user.userId;
    try {
        const snap = await db.collection('jobs')
            .where('contractor_user_id', '==', contractor_id)
            .get();

        const jobs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        jobs.sort((a, b) => (a.position || 0) - (b.position || 0));
        res.json(jobs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch jobs.' });
    }
});

// ── JOBS: CREATE ──────────────────────────────────────────────────────────────
app.post('/api/jobs', requireAuth, async (req, res) => {
    const { client_id, title, description, stage, value, due_date, trade, priority } = req.body;
    const contractor_user_id = req.user.userId;
    if (!title) {
        return res.status(400).json({ error: 'title is required.' });
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
app.put('/api/jobs/:id', requireAuth, async (req, res) => {
    const { title, description, stage, value, due_date, trade, priority, client_id, position } = req.body;
    const contractor_user_id = req.user.userId;
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
app.patch('/api/jobs/:id/stage', requireAuth, async (req, res) => {
    const { stage, position } = req.body;
    const validStages = ['New', 'Scheduled', 'In Progress', 'Completed', 'Invoiced'];
    if (!validStages.includes(stage)) {
        return res.status(400).json({ error: 'Invalid stage.' });
    }
    try {
        const ref = db.collection('jobs').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists || doc.data().contractor_user_id !== req.user.userId) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        const job = doc.data();
        await ref.update({
            stage,
            position: position || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        if (job.lead_id) {
            const customerStatus = stage === 'Completed' || stage === 'Invoiced' ? 'Complete' : stage;
            await db.collection('leads').doc(job.lead_id).update({
                status: customerStatus,
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });
        }
        res.json({ message: 'Stage updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update stage.' });
    }
});

// ── JOBS: DELETE ──────────────────────────────────────────────────────────────
app.delete('/api/jobs/:id', requireAuth, async (req, res) => {
    const contractor_user_id = req.user.userId;
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

// ── APPOINTMENTS ──────────────────────────────────────────────────────────────
// Site-visit / work appointments scheduled between a homeowner and a contractor
// after a quote is accepted. Either party can read; homeowner proposes, contractor
// confirms / declines / counter-proposes; either side can cancel.

const APPT_STATUSES = ['proposed', 'confirmed', 'declined', 'cancelled'];
const APPT_TYPES = ['site_visit', 'work'];

function formatApptForMessage(scheduledAt) {
    const d = new Date(scheduledAt);
    if (Number.isNaN(d.getTime())) return scheduledAt;
    return d.toLocaleString('en-US', {
        weekday: 'short', month: 'short', day: 'numeric',
        hour: 'numeric', minute: '2-digit'
    });
}

// Create an appointment (homeowner proposes, contractor proposes counter)
app.post('/api/appointments', requireAuth, async (req, res) => {
    const { lead_id, scheduled_at, duration_minutes, type, notes } = req.body;
    if (!lead_id || !scheduled_at) {
        return res.status(400).json({ error: 'lead_id and scheduled_at are required.' });
    }
    const when = new Date(scheduled_at);
    if (Number.isNaN(when.getTime())) {
        return res.status(400).json({ error: 'scheduled_at is not a valid date.' });
    }
    if (when.getTime() < Date.now() - 5 * 60 * 1000) {
        return res.status(400).json({ error: 'Pick a time in the future.' });
    }
    const apptType = APPT_TYPES.includes(type) ? type : 'site_visit';

    try {
        const { lead, homeownerId, contractorId } = await resolveLeadParties(lead_id, req.user.userId);
        if (!homeownerId || !contractorId) {
            return res.status(409).json({ error: 'This conversation is not yet matched to both parties.' });
        }

        // Find linked job (if any) for this contractor + lead
        const jobSnap = await db.collection('jobs')
            .where('contractor_user_id', '==', contractorId)
            .where('lead_id', '==', lead_id)
            .limit(1).get();
        const jobId = jobSnap.empty ? null : jobSnap.docs[0].id;

        const ref = await db.collection('appointments').add({
            lead_id,
            job_id: jobId,
            contractor_user_id: contractorId,
            homeowner_user_id: homeownerId,
            proposed_by: req.user.userId,
            proposer_role: req.user.role,
            scheduled_at: admin.firestore.Timestamp.fromDate(when),
            duration_minutes: Number(duration_minutes) > 0 ? Number(duration_minutes) : 60,
            type: apptType,
            status: 'proposed',
            notes: notes ? String(notes).trim().slice(0, 500) : null,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const proposerName = req.user.role === 'contractor'
            ? (await getContractorName(req.user.userId)) || 'Contractor'
            : (lead.name || 'Customer');
        await postSystemMessage(lead_id,
            `${proposerName} proposed a ${apptType === 'site_visit' ? 'site visit' : 'work session'} for ${formatApptForMessage(when)}.`);

        res.status(201).json({ message: 'Appointment proposed', appointmentId: ref.id });
    } catch (err) {
        if (err.status) return res.status(err.status).json({ error: err.message });
        console.error('create appointment error:', err);
        res.status(500).json({ error: 'Failed to create appointment.' });
    }
});

// List appointments — filter by lead_id (both parties) or by current user's role.
app.get('/api/appointments', requireAuth, async (req, res) => {
    const { lead_id } = req.query;
    try {
        let snap;
        if (lead_id) {
            await resolveLeadParties(lead_id, req.user.userId);
            snap = await db.collection('appointments').where('lead_id', '==', lead_id).get();
        } else if (req.user.role === 'contractor') {
            snap = await db.collection('appointments').where('contractor_user_id', '==', req.user.userId).get();
        } else {
            snap = await db.collection('appointments').where('homeowner_user_id', '==', req.user.userId).get();
        }
        const appts = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        appts.sort((a, b) => {
            const at = a.scheduled_at?.toMillis?.() || 0;
            const bt = b.scheduled_at?.toMillis?.() || 0;
            return at - bt;
        });
        res.json(appts);
    } catch (err) {
        if (err.status) return res.status(err.status).json({ error: err.message });
        console.error('list appointments error:', err);
        res.status(500).json({ error: 'Failed to fetch appointments.' });
    }
});

// Confirm / decline / cancel an appointment.
app.patch('/api/appointments/:id', requireAuth, async (req, res) => {
    const { status } = req.body;
    if (!APPT_STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Invalid status.' });
    }
    try {
        const ref = db.collection('appointments').doc(req.params.id);
        const doc = await ref.get();
        if (!doc.exists) return res.status(404).json({ error: 'Appointment not found.' });
        const appt = doc.data();
        const me = req.user.userId;
        const isHomeowner = appt.homeowner_user_id === me;
        const isContractor = appt.contractor_user_id === me;
        if (!isHomeowner && !isContractor) return res.status(403).json({ error: 'Not authorized.' });

        if (status === 'confirmed') {
            // Only the receiving party can confirm (not the proposer).
            if (appt.proposed_by === me) return res.status(403).json({ error: 'The other party must confirm this appointment.' });
            if (appt.status !== 'proposed') return res.status(400).json({ error: 'Only proposed appointments can be confirmed.' });
        }
        if (status === 'declined') {
            if (appt.proposed_by === me) return res.status(403).json({ error: 'You can cancel a proposal you made; only the other party can decline it.' });
            if (appt.status !== 'proposed') return res.status(400).json({ error: 'Only proposed appointments can be declined.' });
        }
        if (status === 'cancelled' && !['proposed', 'confirmed'].includes(appt.status)) {
            return res.status(400).json({ error: 'Already finalized.' });
        }

        await ref.update({
            status,
            decidedAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Mirror confirmed site visits onto the job: stage = Scheduled, due_date = scheduled_at.
        if (status === 'confirmed' && appt.job_id) {
            const when = appt.scheduled_at?.toDate?.() || null;
            const jobUpdate = { stage: 'Scheduled', updatedAt: admin.firestore.FieldValue.serverTimestamp() };
            if (when) jobUpdate.due_date = admin.firestore.Timestamp.fromDate(when);
            await db.collection('jobs').doc(appt.job_id).update(jobUpdate);
            if (appt.lead_id) {
                await db.collection('leads').doc(appt.lead_id).update({
                    status: 'Scheduled',
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
            }
        }

        const when = appt.scheduled_at?.toDate?.() || null;
        const whenStr = when ? formatApptForMessage(when) : '(time TBD)';
        const verb = status === 'confirmed' ? 'confirmed' : status === 'declined' ? 'declined' : 'cancelled';
        await postSystemMessage(appt.lead_id, `Visit ${verb} for ${whenStr}.`);

        res.json({ message: 'Appointment updated' });
    } catch (err) {
        console.error('update appointment error:', err);
        res.status(500).json({ error: 'Failed to update appointment.' });
    }
});

// ── INVOICES: LIST ────────────────────────────────────────────────────────────
app.get('/api/invoices', requireAuth, async (req, res) => {
    const contractor_id = req.user.userId;
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
app.get('/api/subscriptions/:userId', requireAuth, async (req, res) => {
    if (req.user.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    try {
        const doc = await db.collection('users').doc(req.params.userId).get();
        if (!doc.exists) return res.status(404).json({ error: 'User not found.' });
        res.json(doc.data().subscription || {});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch subscription.' });
    }
});

// ── FRONTEND ROUTES ──────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
    res.sendFile(path.join(frontendRoot, 'index.html'));
});

app.get('/:page', (req, res, next) => {
    const pagePath = path.join(frontendRoot, `${req.params.page}.html`);
    if (!fs.existsSync(pagePath)) return next();
    res.sendFile(pagePath);
});

// ── START ─────────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
}
module.exports = app;
