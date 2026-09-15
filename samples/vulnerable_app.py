# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ==========================================
# 1. Loud Vulnerabilities (SAST Targets)
# ==========================================

# Hard-coded Secrets (Mock PoC targets)
AWS_ACCESS_KEY = "MOCK_AKIA_IOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "MOCK_wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_LIVE_API_KEY = "mock_sk_live_51Hj8GvI5uQ4B9wS9xV2n9b8vD7"
DATABASE_PASSWORD = "mock_plaintext_db_pass_123!"

# Mock Database Setup
def get_db_connection():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT, is_admin BOOLEAN)')
    conn.execute("INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1)")
    conn.execute("INSERT INTO users (username, password, email, is_admin) VALUES ('buyer', 'password123', 'buyer@example.com', 0)")
    return conn

# SQL Injection (SQLi)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    # VULNERABLE: Direct string interpolation of user inputs into SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "message": f"Welcome back, {user['username']}!", "is_admin": bool(user['is_admin'])})
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401

# Reflected Cross-Site Scripting (XSS)
@app.route('/receipt', methods=['GET'])
def receipt():
    customer_name = request.args.get('customer_name', 'Valued Customer')
    # VULNERABLE: Direct reflection of parameter input in HTML without sanitization/escaping
    html_content = f"""
    <html>
        <body>
            <h1>Thank you for your order, {customer_name}!</h1>
            <p>Your transaction was successful.</p>
        </body>
    </html>
    """
    return render_template_string(html_content)


# ==========================================
# 2. Silent Vulnerabilities (Business Logic Targets)
# ==========================================

# Business Logic Flaw: Client-Side Price Trust
@app.route('/checkout', methods=['POST'])
def checkout():
    data = request.get_json() or {}
    item_id = data.get('item_id')
    quantity = data.get('quantity', 1)
    
    # VULNERABLE: Trusting the price passed in the client payload instead of querying the catalog db!
    item_price = data.get('price') 
    
    if item_price is None:
        return jsonify({"error": "Price is required"}), 400
        
    total_amount = float(item_price) * int(quantity)
    return jsonify({
        "status": "success",
        "item_id": item_id,
        "quantity": quantity,
        "total_billed": total_amount,
        "message": f"Successfully charged ${total_amount:.2f} using payment gateway API."
    })

# Insecure Direct Object Reference (IDOR) & Mass Assignment
@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.get_json() or {}
    
    # VULNERABLE IDOR: Trusting user_id directly from JSON payload instead of checking session authentication token
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # VULNERABLE Mass Assignment: Looping over user-provided keys to construct query without filtering admin field updates
    update_parts = []
    update_values = []
    for key, value in data.items():
        if key == 'user_id':
            continue
        update_parts.append(f"{key} = ?")
        update_values.append(value)
        
    if update_parts:
        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_parts)} WHERE id = ?"
        cursor.execute(query, update_values)
        conn.commit()
        
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    updated_user = cursor.fetchone()
    conn.close()
    
    if updated_user:
        return jsonify({
            "status": "success",
            "user": {
                "id": updated_user['id'],
                "username": updated_user['username'],
                "email": updated_user['email'],
                "is_admin": bool(updated_user['is_admin'])
            }
        })
    return jsonify({"error": "User not found"}), 404

# Command Injection (RCE) (SAST)
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '8.8.8.8')
    # VULNERABLE RCE: User-controlled input passed directly to system shell execution
    command = f"ping -c 1 {host}"
    response = os.popen(command).read()
    return jsonify({"status": "completed", "output": response})

if __name__ == '__main__':
    app.run(port=5000)
