const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'cyclo-secret-key-2026'; // In a real app, use env variable

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'database.sqlite');

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static(__dirname)); // Serve frontend files

// Supabase Configuration (Optional - User to fill in)
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
    supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    console.log('Supabase backup enabled.');
} else {
    console.log('Supabase credentials missing. Cloud backup disabled.');
}

// Database Setup
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('Error opening database:', err);
    else {
        console.log('Connected to local SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_id TEXT,
            date TEXT,
            supplier TEXT,
            invoice TEXT,
            total_invoice_amount REAL,
            payments TEXT,
            supplier_due TEXT,
            cyclo_due TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error('Error creating table:', err);
        });

        // Settings table for global config
        db.run(`CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )`);

        // Users table for authentication
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )`, async (err) => {
            if (!err) {
                // Check if admin exists, if not create default
                db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
                    if (!row) {
                        const hashedPassword = await bcrypt.hash('admin123', 10);
                        db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
                            ['Admin User', 'admin@cyclo.com', hashedPassword, 'admin']);
                        console.log('Default admin created: admin@cyclo.com / admin123');
                    }
                });
            }
        });
    }
});

// Middlewares
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Direct access denied. Please login.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Session expired or invalid.' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') next();
    else res.status(403).json({ error: 'Admin access required.' });
};

// API Endpoints

// --- AUTH ENDPOINTS ---

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    });
});

// --- USER MANAGEMENT (Admin Only) ---

app.get('/api/users', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT id, name, email, role FROM users`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
        [name, email, hashedPassword, role || 'user'], function (err) {
            if (err) return res.status(500).json({ error: 'Email already exists or database error' });
            res.json({ id: this.lastID, name, email, role });
        });
});

app.delete('/api/users/:id', authenticateToken, isAdmin, (req, res) => {
    const targetId = req.params.id;

    // Safety Trigger 1: Prevent self-deletion
    if (String(req.user.id) === String(targetId)) {
        return res.status(400).json({ error: "Safety Trigger: You cannot delete your own account while logged in." });
    }

    // Safety Trigger 2: Prevent deletion of other admins
    db.get(`SELECT role FROM users WHERE id = ?`, [targetId], (err, user) => {
        if (err || !user) return res.status(404).json({ error: "User not found." });

        if (user.role === 'admin') {
            return res.status(403).json({ error: "Operation Blocked: Administrative accounts cannot be deleted. Only standard users can be removed." });
        }

        db.run(`DELETE FROM users WHERE id = ?`, [targetId], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'User deleted' });
        });
    });
});

// GET all entries with sorting
app.get('/api/data', authenticateToken, (req, res) => {
    const { sort = 'date', order = 'DESC' } = req.query;
    const validColumns = ['date', 'supplier', 'invoice', 'total_invoice_amount', 'supplier_due', 'cyclo_due'];
    const orderBy = validColumns.includes(sort) ? sort : 'date';
    const direction = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    db.all(`SELECT * FROM entries ORDER BY ${orderBy} ${direction}`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Parse payments JSON string
        const entries = rows.map(row => ({
            ...row,
            payments: JSON.parse(row.payments || '[]')
        }));
        res.json(entries);
    });
});

// POST new entry
app.post('/api/data', authenticateToken, async (req, res) => {
    const entry = req.body;
    const paymentsStr = JSON.stringify(entry.payments || []);

    const query = `INSERT INTO entries (original_id, date, supplier, invoice, total_invoice_amount, payments, supplier_due, cyclo_due) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [entry.id, entry.date, entry.supplier, entry.invoice, entry.total_invoice_amount, paymentsStr, entry.supplier_due, entry.cyclo_due];

    db.run(query, params, async function (err) {
        if (err) return res.status(500).json({ error: err.message });

        const newId = this.lastID;
        const result = { ...entry, id: newId };

        // Supabase Backup
        if (supabase) {
            try {
                await supabase.from('entries').insert([{ ...result, payments: paymentsStr }]);
            } catch (sErr) { console.error('Supabase Sync Error:', sErr); }
        }

        res.json(result);
    });
});

// PUT update entry
app.put('/api/data/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const entry = req.body;
    const paymentsStr = JSON.stringify(entry.payments || []);

    const query = `UPDATE entries SET 
                    date = ?, supplier = ?, invoice = ?, 
                    total_invoice_amount = ?, payments = ?, 
                    supplier_due = ?, cyclo_due = ? 
                   WHERE id = ?`;
    const params = [entry.date, entry.supplier, entry.invoice, entry.total_invoice_amount, paymentsStr, entry.supplier_due, entry.cyclo_due, id];

    db.run(query, params, async function (err) {
        if (err) return res.status(500).json({ error: err.message });

        if (supabase) {
            try {
                await supabase.from('entries').update({ ...entry, payments: paymentsStr }).eq('id', id);
            } catch (sErr) { console.error('Supabase Sync Error:', sErr); }
        }

        res.json({ message: 'Updated successfully' });
    });
});

// DELETE entry
app.delete('/api/data/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM entries WHERE id = ?`, id, async function (err) {
        if (err) return res.status(500).json({ error: err.message });

        if (supabase) {
            try {
                await supabase.from('entries').delete().eq('id', id);
            } catch (sErr) { console.error('Supabase Sync Error:', sErr); }
        }

        res.json({ message: 'Deleted successfully' });
    });
});

// BULK Sync (Overwrite)
app.post('/api/data/sync', authenticateToken, (req, res) => {
    console.log('POST /api/data/sync - Initializing sync');
    const entries = req.body;
    if (!Array.isArray(entries)) return res.status(400).json({ error: 'Data must be an array' });

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run('DELETE FROM entries');
        const stmt = db.prepare(`INSERT INTO entries (original_id, date, supplier, invoice, total_invoice_amount, payments, supplier_due, cyclo_due) 
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);

        entries.forEach(entry => {
            stmt.run(entry.id, entry.date, entry.supplier, entry.invoice, entry.total_invoice_amount, JSON.stringify(entry.payments || []), entry.supplier_due, entry.cyclo_due);
        });

        stmt.finalize();
        db.run('COMMIT', (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: `Successfully synced ${entries.length} entries` });
        });
    });
});

// Settings Endpoints
app.get('/api/settings', authenticateToken, (req, res) => {
    db.get(`SELECT value FROM settings WHERE key = 'app_settings'`, (err, row) => {
        if (err) res.status(500).json({ error: err.message });
        else res.json(row ? JSON.parse(row.value) : null);
    });
});

app.post('/api/settings', authenticateToken, (req, res) => {
    const settings = JSON.stringify(req.body);
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('app_settings', ?)`, [settings], (err) => {
        if (err) res.status(500).json({ error: err.message });
        else res.json({ message: 'Settings saved' });
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
