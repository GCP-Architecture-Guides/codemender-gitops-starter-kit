package main
// CodeMender E2E Production Scan Trigger comment v3

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	_ "github.com/mattn/go-sqlite3"
)

// 1. Hardcoded Secrets (SAST)
const SlackToken = "xoxb-EXAMPLE-NOT-A-REAL-TOKEN"
const DBPassword = "database_root_plaintext_pass_999!"

type UserProfile struct {
	UserID   int    `json:"user_id"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	IsAdmin  bool   `json:"is_admin"`
}

type Invoice struct {
	UUID     string  `json:"uuid"`
	Amount   float64 `json:"amount"`
	Customer string  `json:"customer"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT, is_admin BOOLEAN)")
	db.Exec("INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1)")
	db.Exec("CREATE TABLE invoices (uuid TEXT, amount REAL, customer TEXT)")
	db.Exec("INSERT INTO invoices (uuid, amount, customer) VALUES ('fec63596-391e-45d4-bf77-7e40c12c3b7a', 1500.0, 'buyer')")
}

// 2. SQL Injection (SAST)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE SQL Injection: Direct string interpolation into raw query
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s' AND password = '%s'", username, password)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if rows.Next() {
		w.Write([]byte("Welcome back!"))
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// 3. Reflected XSS (SAST)
func receiptHandler(w http.ResponseWriter, r *http.Request) {
	customerName := r.URL.Query().Get("customer_name")
	if customerName == "" {
		customerName = "Customer"
	}
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE Reflected XSS: Writing raw unsanitized URL inputs directly back to the response
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Thank you, %s!</h1></body></html>", customerName)))
}

// 4. IDOR & Mass Assignment (Business Logic Flaw)
func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var profile UserProfile
	err := json.NewDecoder(r.Body).Decode(&profile)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// VULNERABLE IDOR: Trusts the user_id inside JSON body without auth validation
	// VULNERABLE Mass Assignment: updates is_admin directly from input struct properties
	query := fmt.Sprintf("UPDATE users SET email=$1, full_name=$2, is_admin=$3 WHERE id=%d", profile.UserID)
	_, err = db.Exec(query, profile.Email, profile.FullName, profile.IsAdmin)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status": "success"}`))
}

// 5. UUID-based IDOR (Business Logic Flaw)
func viewInvoiceHandler(w http.ResponseWriter, r *http.Request) {
	invoiceUUID := r.URL.Query().Get("uuid")
	if invoiceUUID == "" {
		http.Error(w, "uuid is required", http.StatusBadRequest)
		return
	}
	
	// VULNERABLE IDOR: Trusts user-provided UUID directly to fetch database records
	// without checking if the authenticated session user owns this specific invoice.
	query := fmt.Sprintf("SELECT uuid, amount, customer FROM invoices WHERE uuid = '%s'", invoiceUUID)
	row := db.QueryRow(query)
	
	var inv Invoice
	err := row.Scan(&inv.UUID, &inv.Amount, &inv.Customer)
	if err != nil {
		http.Error(w, "Invoice not found", http.StatusNotFound)
		return
	}
	
	json.NewEncoder(w).Encode(inv)
}

func main() {
	initDB()
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/receipt", receiptHandler)
	http.HandleFunc("/api/profile/update", updateProfileHandler)
	http.HandleFunc("/api/invoice", viewInvoiceHandler)
	http.ListenAndServe(":8080", nil)
}
