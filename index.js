const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const app = express();
const db = new Database('voting_system.db');

app.use(express.json());
app.use(express.static('public'));

// --- DATABASE INITIALIZATION ---
db.prepare(`
  CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dept_name TEXT UNIQUE
  ) 
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT CHECK(role IN ('voter', 'admin')),
    department_id INTEGER,
    has_voted INTEGER DEFAULT 0
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    position TEXT NOT NULL,
    department_id INTEGER,
    votes_count INTEGER DEFAULT 0,
    FOREIGN KEY (department_id) REFERENCES departments(id)
  )
`).run();

// --- MIDDLEWARE ---
const isAdmin = (req, res, next) => {
    const user_role = req.headers['user-role']; 
    if (user_role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Access denied. Admins only!" });
    }
};

// --- AUTH ROUTES ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = db.prepare(`
            SELECT users.*, departments.dept_name 
            FROM users 
            LEFT JOIN departments ON users.department_id = departments.id 
            WHERE username = ?
        `).get(username);

        if (user && await bcrypt.compare(password, user.password)) {
            res.json({ 
                user: { 
                    id: user.id, 
                    username: user.username, 
                    role: user.role, 
                    has_voted: user.has_voted, 
                    dept_name: user.dept_name || 'General' 
                } 
            });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});
// New route to get all candidates for the ballot
app.get('/candidates', (req, res) => {
    try {
        const candidates = db.prepare(`
            SELECT candidates.id, candidates.name, candidates.position, 
                   IFNULL(departments.dept_name, 'General') AS dept_name 
            FROM candidates 
            LEFT JOIN departments ON candidates.department_id = departments.id
        `).all();
        res.json(candidates);
    } catch (err) {
        console.error("Error fetching candidates:", err);
        res.status(500).json({ error: "Failed to load candidates list." });
    }
});
// Add a new candidate
app.post('/admin/add-candidate', isAdmin, (req, res) => {
    const { name, position, dept_name } = req.body;
    
    try {
        // 1. Find or create the department ID
        let dept = db.prepare('SELECT id FROM departments WHERE dept_name = ?').get(dept_name || 'General');
        
        if (!dept) {
            const info = db.prepare('INSERT INTO departments (dept_name) VALUES (?)').run(dept_name || 'General');
            dept = { id: info.lastInsertRowid };
        }

        // 2. Insert the candidate
        db.prepare(`
            INSERT INTO candidates (name, position, department_id, votes_count) 
            VALUES (?, ?, ?, 0)
        `).run(name, position, dept.id);

        res.json({ message: "Candidate added successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to add candidate. Name might already exist." });
    }
});
// --- VOTING ---
app.post('/vote', (req, res) => {
    const { user_id, candidate_id } = req.body;
    try {
        const processVote = db.transaction(() => {
            db.prepare('UPDATE candidates SET votes_count = votes_count + 1 WHERE id = ?').run(candidate_id);
            db.prepare('UPDATE users SET has_voted = 1 WHERE id = ?').run(user_id);
        });
        processVote();
        res.json({ message: "Vote cast successfully!" });
    } catch (err) {
        res.status(500).json({ error: "Failed to process vote." });
    }
});

// --- ADMIN MANAGEMENT ---
app.get('/admin/results', (req, res) => {
    const results = db.prepare('SELECT * FROM candidates ORDER BY votes_count DESC').all();
    res.json(results);
});

app.get('/admin/voters', isAdmin, (req, res) => {
    const voters = db.prepare(`
        SELECT username, role, 
        CASE WHEN has_voted = 1 THEN 'Voted ✅' ELSE 'Pending 🕒' END AS status 
        FROM users
    `).all();
    res.json(voters);
});

app.delete('/admin/delete-candidate/:id', isAdmin, (req, res) => {
    db.prepare('DELETE FROM candidates WHERE id = ?').run(req.params.id);
    res.json({ message: "Candidate deleted" });
});

app.post('/admin/reset-election', isAdmin, (req, res) => {
    const reset = db.transaction(() => {
        db.prepare('UPDATE users SET has_voted = 0').run();
        db.prepare('UPDATE candidates SET votes_count = 0').run();
    });
    reset();
    res.json({ message: "Election reset" });
});
// Registration Route
app.post('/register', async (req, res) => {
    const { username, password, department_id } = req.body;
    
    try {
        // 1. Hash the password for security
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 2. Insert into database (Role is strictly 'voter')
        const stmt = db.prepare(`
            INSERT INTO users (username, password, role, department_id, has_voted) 
            VALUES (?, ?, 'voter', ?, 0)
        `);
        
        stmt.run(username, hashedPassword, department_id || null);
        
        res.status(201).json({ message: "Account created successfully!" });
    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            res.status(400).json({ error: "Username already exists." });
        } else {
            res.status(500).json({ error: "Registration failed." });
        }
    }
});
app.listen(3000, () => console.log('Server running on http://localhost:3000'));