package com.example.vulnerableserver.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class VulnerableController {

    // 1. Hardcoded Secrets (SAST)
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String DB_PASSWORD = "plaintext_mysql_password_root_123";

    // 2. SQL Injection (SAST)
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            Statement stmt = conn.createStatement();
            
            // VULNERABLE SQL Injection: Query built using raw string concatenation
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                return ResponseEntity.ok("Welcome back " + rs.getString("username"));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Database error: " + e.getMessage());
        }
    }

    // 3. Reflected Cross-Site Scripting (XSS) (SAST)
    @GetMapping(value = "/receipt", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String receipt(@RequestParam(value = "customer_name", defaultValue = "Valued Customer") String customerName) {
        // VULNERABLE Reflected XSS: Returning user inputs directly inside unescaped HTML response
        return "<html><body><h1>Thank you for your order, " + customerName + "!</h1></body></html>";
    }

    // 4. Business Logic Flaw: Client-Side Price Trust (E-Commerce)
    @PostMapping("/checkout")
    public ResponseEntity<String> checkout(@RequestBody Map<String, Object> payload) {
        String itemId = (String) payload.get("item_id");
        int quantity = (Integer) payload.get("quantity");
        
        // VULNERABLE: Reading product price directly from user cart payload instead of database catalog!
        double price = (Double) payload.get("price");
        
        double totalBilled = price * quantity;
        
        String responseMessage = String.format("Successfully checked out item: %s, quantity: %d. Total charged: $%.2f", 
            itemId, quantity, totalBilled);
            
        return ResponseEntity.ok(responseMessage);
    }

    // 5. Path Traversal / Arbitrary File Read (SAST)
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam("file") String filename) {
        try {
            // VULNERABLE Path Traversal: direct string concatenation without checks
            java.io.File file = new java.io.File("/var/reports/" + filename);
            byte[] fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(fileBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
