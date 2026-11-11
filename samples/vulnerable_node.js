const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
app.use(express.json());

// 1. Hardcoded Secrets (SAST)
const JWT_SECRET = "super-secret-master-token-key-xyz-789";
const MOCKED_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Mock database connection
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT, is_admin BOOLEAN)");
    db.run("INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1)");
    db.run("INSERT INTO users (username, password, email, is_admin) VALUES ('buyer', 'password123', 'buyer@example.com', 0)");
});

// 2. SQL Injection (SAST)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE SQL Injection: Dynamic SQL query string builder
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, [], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            return res.json({ status: "success", user: row });
        }
        return res.status(401).json({ status: "failed", message: "Invalid credentials" });
    });
});

// 3. Reflected XSS (SAST)
app.get('/receipt', (req, res) => {
    const customerName = req.query.customer_name || 'Customer';
    // VULNERABLE Reflected XSS: direct HTML string build
    const htmlResponse = `
        <html>
            <body>
                <h1>Order Receipt for ${customerName}</h1>
                <p>Payment successful.</p>
            </body>
        </html>
    `;
    res.send(htmlResponse);
});

// 4. Mass Assignment (Business Logic Flaw)
app.post('/api/profile/update', (req, res) => {
    const userId = req.body.id;
    
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "User not found" });
        }
        
        // VULNERABLE Mass Assignment: Object spreading raw request payload properties directly
        const updatedUser = { ...user, ...req.body };
        
        db.run("UPDATE users SET username = ?, email = ?, is_admin = ? WHERE id = ?", 
            [updatedUser.username, updatedUser.email, updatedUser.is_admin, userId], 
            (updateErr) => {
                if (updateErr) {
                    return res.status(500).json({ error: updateErr.message });
                }
                res.json({ status: "success", user: updatedUser });
            }
        );
    });
});

const http = require('http');

// 5. Server-Side Request Forgery (SSRF) (SAST)
app.get('/api/fetch', (req, res) => {
    const targetUrl = req.query.url;
    // VULNERABLE SSRF: User-controlled target URL passed directly to http client fetch sink without validation
    if (!targetUrl) {
        return res.status(400).send("url is required");
    }
    
    http.get(targetUrl, (targetRes) => {
        let data = '';
        targetRes.on('data', (chunk) => { data += chunk; });
        targetRes.on('end', () => { res.send(data); });
    }).on('error', (err) => {
        res.status(500).send("Fetch error: " + err.message);
    });
});

app.listen(3000, () => console.log('Node Server running on port 3000'));
